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
    origin='else if(engine=="x86_iter" && bits==32 && X86_disasmIter32) row=cs_span<X86_disasmIter32>(bytes.data()+f.offset,f.size,handle,insn,f.ip,mode);\n        '
    assert inc.count(origin)==1
    inc=inc.replace(origin,'')
    inc='#include <valgrind/callgrind.h>\n'+inc
    inc=inc.replace('Result warm=run(1);','Result warm=run(1); CALLGRIND_ZERO_STATS;')
    inc=inc.replace('Result timed=run(reps);','CALLGRIND_TOGGLE_COLLECT; Result timed=run(reps); CALLGRIND_TOGGLE_COLLECT;')
    (w/'functions.cpp').write_text(inc);run(['clang++','-O3','-DNDEBUG','-std=c++17','-I',base,'-I',base/'include','-c',w/'functions.cpp','-o',w/'driver.o'],'driver')
    profile=['-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+os.environ['CC'],'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',*['-DCAPSTONE_'+arch+'_SUPPORT=ON' for arch in ['X86','ARM','AARCH64','MIPS']],'-DCMAKE_C_FLAGS_RELEASE=-O3 -DNDEBUG -fomit-frame-pointer '+('-Wno-error=discarded-qualifiers' if os.environ['CC']=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),'-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_SHARED_LIBS=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=ON']
    profile += ['-DCMAKE_EXPORT_COMPILE_COMMANDS=ON','-DCAPSTONE_MIPS_PRECHECK_PRINTED_ALIAS=ON','-DCAPSTONE_MIPS_FINAL_OUTPUT_TRIM=ON','-DCAPSTONE_X86_NEAR_INDIRECT_OUTPUT=ON']
    data=json.loads((r/'experiment.json').read_text())
    b=w/'build';exe={}
    run(['cmake','-S',base,'-B',b,*profile],'configure')
    commands=json.loads((b/'compile_commands.json').read_text())
    owners={opt:sorted({Path(row['file']).name for row in commands if '-D'+opt in row['command'].split() or '-D'+opt+'=1' in row['command'].split()}) for opt in ('CAPSTONE_MIPS_PRECHECK_PRINTED_ALIAS','CAPSTONE_MIPS_FINAL_OUTPUT_TRIM','CAPSTONE_X86_NEAR_INDIRECT_OUTPUT')}
    assert list(owners.values())==[['MipsMapping.c'],['MipsInstPrinter.c'],['X86Sse64Output.c']]
    save('flag-owners.json',owners)
    obj=w/'driver.o'
    assert 'cs_disasm_iter' in sp.check_output(['nm','-u',obj],text=True)
    save('consumer-object.json',dict(sha256=sha(obj)))
    for label,tree in data['trees'].items():
        assert sp.check_output(['git','-C',base,'write-tree'],text=True).strip()==tree
        run(['cmake','--build',b,'--parallel','4','--target','capstone_static',*data['tests']],'build-'+label)
        run(['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(data['tests'])+')$'],'units-'+label)
        libs=[b/'libcapstone.a',ad/'target/release/libiced_compare.a','-lpthread','-ldl','-lm']
        target=w/('run-'+label)
        run(['clang++',obj,'-Wl,--undefined=cs_disasm_iter','-Wl,--undefined=X86_disasmIterText',*libs,'-o',target],'link-'+label)
        symbols={line.split()[-1] for line in sp.check_output(['nm','--defined-only',target],text=True).splitlines() if line.strip()}
        assert {'cs_disasm_iter','X86_disasmIter32','X86_disasmIterText'}<=symbols
        exe[label]=target
    save('tested-trees.json',data)
    import frozen_deb as deb
    run(['clang++','-O2','-I',base/'include',r/'vectors.cpp',b/'libcapstone.a','-o',w/'vectors'],'vectors');reported=[];manifest={}
    from costs import parse
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
        audit=[sp.check_output([exe[k],'audit','0','1',f,intervals,str(bits)],text=True) for k in data['trees']]
        assert len(audit)==1
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
        for mode in range(5):
            engines=[('released','capstone')]+([('released','x86_iter')] if mode else [])
            if mode<=2:engines+=[('released','iced____')]+([('released','fast____')]if mode else [])
            reference=None
            for variant,engine in engines:
                ident=name+'-'+str(mode)+'-'+variant+'-'+engine;raw=w/'active.out';packed=w/'active.gz'
                args=[str(exe[variant]),engine,str(mode),'1',str(f),str(intervals),str(bits)]
                native=list(map(int,sp.check_output(args,text=True).split()));assert len(native)==6 and native[2]>0
                if reference is None:reference=native
                assert native[2:5]==reference[2:5]
                if engine in ('x86_iter','capstone'):assert native[2:]==reference[2:]
                result=sp.run(['valgrind','--tool=callgrind','--cache-sim=yes','--branch-sim=yes','--dump-instr=yes','--collect-atstart=no','--callgrind-out-file='+str(raw),*args],capture_output=True,text=True)
                if result.returncode:raise RuntimeError((ident,result.stderr))
                measured=list(map(int,result.stdout.split()));assert measured[2:]==native[2:]
                with raw.open('rb')as inp,gzip.open(packed,'wb',compresslevel=1)as out:shutil.copyfileobj(inp,out)
                events,tot,cost,edges=parse(packed)
                assert set(['Ir','Dr','Dw','Bc','Bi'])<=set(events) and len(tot)==len(events) and all(x>=0 for x in tot)
                funcs=[]
                for (obj,fn),rows in cost.items():
                    aggregate=[sum(v[i] for v in rows.values()) for i in range(len(events))]
                    funcs.append(dict(fn=fn,object=Path(obj).name,events=dict(zip(events,aggregate))))
                funcs.sort(key=lambda x:x['events']['Ir'],reverse=True)
                assert sum(v['events']['Ir']for v in funcs)==tot[events.index('Ir')]
                call_counts={}
                for (caller,callee),count in edges.items():call_counts[callee]=call_counts.get(callee,0)+count
                relevant={k:v for k,v in call_counts.items()if k in ('cs_decode_full_insn','cs_regs_access','X86_Intel_printInst','X86_getInstruction','X86_disasmIter32','X86_disasmIterText','X86_writeSimpleDetail')or 'Formatter' in k or 'decode_out' in k}
                reported.append(dict(case=name,mode=mode,tree=variant,engine=engine,signature=measured[2:],totals=dict(zip(events,tot)),top=funcs[:55],calls=relevant,sha256=sha(raw)))
                raw.unlink();packed.unlink();save('counts.json',reported)
        print(name,panel,len(sel),flush=True)
    assert len(reported)==56 and len(manifest)==4,(len(reported),len(manifest))
    save('complete.json',dict(cases=len(reported),success=True,hardware_timing=False,scope='Timed loop only after a full warmup; per-symbol exclusive totals independently summed against Callgrind.'))
w=Path(tempfile.mkdtemp(prefix='capstone-vex32-iced-'))
try:
    if hasattr(os,'sched_setaffinity'): os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    main(w)
finally:
    files=[v for v in w.rglob('*') if v.is_file()];amount=sum(v.stat().st_size for v in files);shutil.rmtree(w);save('cleanup.json',dict(removed=not w.exists(),bytes=amount,files=len(files)))
