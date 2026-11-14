"""Measure exact, common-boundary PE function bodies and three additional ELF text sections."""
from pathlib import Path
import os, platform, hashlib, importlib.util, json, math, shutil, statistics, subprocess as sp, tempfile
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
    reference='a7787ac5c7c0ead02a3c46c85cdcfcb482dc6343'
    assert sp.check_output(['git','-C',base,'rev-parse',reference],text=True).strip()==reference
    iced='8b8d90b13374fbf38e7279749e48c673f4ec243a'
    checkout=w/'iced';checkout.mkdir();tar=w/'iced.tar'
    run(['git','init','--bare',w/'iced-git'],'iced-repo');run(['git','-C',w/'iced-git','fetch','--depth','1','https://github.com/NeverSight/iced.git',iced],'iced-fetch');run(['git','-C',w/'iced-git','archive','--format=tar','-o',tar,iced,'src/rust/iced-x86'],'iced-archive');run(['tar','-xf',tar,'-C',checkout],'iced-extract');tar.unlink()
    ad=w/'adapter';ad.mkdir();src=(lab/'iced.rs').read_text().replace('repeats: u32,\n    output:', 'repeats: u32,\n    ip: u64,\n    output:').replace('bytes, 0x100000,','bytes, ip,').replace('set_ip(0x100000 +','set_ip(ip +')
    src=src.replace('InstructionInfoFactory, IntelFormatter,','InstructionInfoFactory, IntelFormatter, FastFormatter,').replace('    formatter: IntelFormatter,','    formatter: IntelFormatter,\n    fast: FastFormatter,\n    fast_enabled: bool,').replace('        mode,','        mode: mode & 3,\n        fast_enabled: mode & 8 != 0,\n        fast: FastFormatter::new(),')
    old='state.formatter.format(&instruction, &mut state.text);';assert src.count(old)==1;src=src.replace(old,'if state.fast_enabled {state.fast.format(&instruction, &mut state.text);} else {state.formatter.format(&instruction, &mut state.text);}')
    trace=(r/'iced-trace.rs').read_text().replace('iced_trace(input:', 'iced_trace(bits:u32,input:').replace('with_ip(64,','with_ip(bits,');(ad/'iced.rs').write_text(src+trace);shutil.copyfile(lab/'Cargo.lock',ad/'Cargo.lock')
    (ad/'Cargo.toml').write_text('[package]\nname="iced_compare"\nversion="0.1.0"\nedition="2021"\n[lib]\ncrate-type=["staticlib"]\npath="iced.rs"\n[dependencies]\niced-x86={path="../iced/src/rust/iced-x86",default-features=false,features=["std","decoder","intel","instr_info","fast_fmt"]}\n[profile.release]\npanic="abort"\nopt-level=3\n');run(['cargo','build','--locked','--release'],'iced-build',ad)
    save('variants.json',dict(control='byte-identical baseline copy',integer='301 homogeneous VEX2 opcode plans, based on '+reference,aa='byte-identical reference',output='Grouped ModRM VEX2 operands and legality in both x86 modes'))
    save('entrypoints.json',dict(scan='cs_disasm_iter',format='X86_disasmIter',detail='X86_disasmIter',consumer='Decoder::decodePhysical via X86_disasmIter, NeverD dev ddf30e5255af3aa7fa071d756ada080c4c957071'))
    inc=(r/'driver.cpp').read_text().replace('size_t iced_trace(const','size_t iced_trace(unsigned, const').replace('if(argc!=6)','if(argc!=7)').replace('  csh handle=0;','  unsigned bits=std::stoul(argv[6]);\n  csh handle=0;').replace('cs_open(CS_ARCH_X86,CS_MODE_64,','cs_open(CS_ARCH_X86,bits==32?CS_MODE_32:CS_MODE_64,').replace('iced_create(64,mode)','iced_create(bits,mode)').replace('iced_trace(ptr,','iced_trace(bits,ptr,')
    inc=inc.replace('iced_create(bits,mode)','iced_create(bits,mode | (engine=="fast" ? 8 : 0))').replace('engine!="capstone" && engine!="iced"','engine!="capstone" && engine!="iced" && engine!="fast"')
    inc=inc.replace('if (mode>2 ||','if (mode>4 ||').replace('mode==2 ? CS_OPT_ON','mode>=2 ? CS_OPT_ON')
    inc=inc.replace('if (mode == 2) {','if (mode == 2 || mode == 4) {\n        if (mode == 2) {').replace('        const auto &x = insn->detail->x86;', '        }\n        const auto &x = insn->detail->x86;')
    assert inc.count('iced_trace(bits,ptr,')==1
    (w/'functions.cpp').write_text(inc);run(['clang++','-O3','-DNDEBUG','-std=c++17','-I',base/'include','-c',w/'functions.cpp','-o',w/'driver.o'],'driver')
    profile=['-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+os.environ['CC'],'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',*['-DCAPSTONE_'+arch+'_SUPPORT=ON' for arch in ['X86','ARM','AARCH64','MIPS']],'-DCMAKE_C_FLAGS_RELEASE=-O3 -DNDEBUG -fomit-frame-pointer '+('-Wno-error=discarded-qualifiers' if os.environ['CC']=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),'-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_SHARED_LIBS=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF']
    tree=w/'tree';run(['git','clone','-q','--shared','--no-checkout',base,tree],'capstone-clone');run(['git','checkout','-q','--detach',reference],'capstone-checkout',tree);b=w/'build';run(['cmake','-S',tree,'-B',b,*profile],'configure');evidence={};exe={}
    objects={}
    for label in ('integer','aa','output'):
        if label=='aa':
            exe[label]=w/'baseline-copy';shutil.copy2(exe['integer'],exe[label]);continue
        patches=[r/'baseline.patch'] if label=='integer' else [r/'dispatch.patch']
        for patch in patches: run(['git','apply',patch],'apply-'+label+'-'+patch.stem,tree)
        run(['cmake','--build',b,'--target','capstone_static','--parallel','4'],'build-'+label)
        objroot=b/'CMakeFiles/capstone.dir'
        objects[label]={str(path.relative_to(objroot)):sha(path) for path in objroot.rglob('*.o')}
        assert len(objects[label])>30
        if label=='output':
            changed={n for n in objects[label]if objects[label][n]!=objects['integer'][n]}
            assert changed=={'arch/X86/X86DisassemblerDecoder.c.o'},changed
            save('objects.json',dict(changed=sorted(changed),total=len(objects[label])))
        code=inc.replace('#include <capstone/capstone.h>','#include <capstone/capstone.h>\n#include "X86ScanAdapter.h"');old='bool ok = cs_disasm_iter(handle, &cursor, &left, &ip, insn);';assert code.count(old)==1;code=code.replace(old,'bool ok = mode ? X86_disasmIter(handle,&cursor,&left,&ip,insn) : cs_disasm_iter(handle,&cursor,&left,&ip,insn);');(w/'owned.cpp').write_text(code);obj=w/'owned.o';run(['clang++','-O3','-DNDEBUG','-std=c++17','-I',base/'include','-I',tree/'arch/X86','-c',w/'owned.cpp','-o',obj],'owned-driver-'+label)
        target=w/('run-'+label);run(['clang++',obj,b/'libcapstone.a',ad/'target/release/libiced_compare.a','-lpthread','-ldl','-lm','-o',target],'link-'+label);exe[label]=target
        run(['git','reset','--hard',reference],'restore-'+label,tree)
        run(['git','clean','-fdx'],'remove-generated-'+label,tree)
        assert not sp.check_output(['git','-C',tree,'status','--porcelain'])
    run(['git','apply',r/'dispatch.patch'],'apply-census',tree)
    with (tree/'arch/X86/X86OutputIterator.c').open('a')as f:f.write('\nbool census_output(csh h,const uint8_t*p,size_t n,cs_insn*i){uint16_t len;return X86_trySimpleOutput((cs_struct*)(uintptr_t)h,p,n,i,&len);}\n')
    run(['cmake','--build',b,'--target','capstone_static','--parallel','4'],'census-build')
    run(['clang++','-O2','-std=c++17','-I',tree/'include',r/'census.cpp',b/'libcapstone.a','-o',w/'census'],'census-link')
    import deb
    run(['clang++','-O2','-I',base/'include',r/'vectors.cpp',b/'libcapstone.a','-o',w/'vectors'],'vectors');reported=[];manifest={}
    for name,bits,f,spans,source in deb.prepare(w):
        intervals=w/(name+'.tsv');intervals.write_text(''.join('%d %d %d\n'%v for v in spans));raw=sp.check_output([exe['integer'],'audit','0','1',f,intervals,str(bits)],text=True);rows=[list(map(int,x.split())) for x in raw.splitlines()];views=[list(map(int,x.split()))for x in sp.check_output([w/'vectors',str(bits),f,intervals],text=True).splitlines()];assert len(views)==len(rows)==len(spans)
        common=[(q[:3],vw)for q,vw in zip(rows,views)if q[1]==q[5]];assert common
        manifest[name]=dict(source,common_functions=len(common),common_bytes=sum(z[0][1]for z in common),host=platform.platform(),iced_revision=iced,selection='all FDE and symbol extents with identical instruction boundaries; SIMD subset has at least 8 explicit vector-register instructions and at least 15% vector instructions')
        for panel in (['all-functions','simd-functions'] if name!='jpeg-avx2-i386' else ['simd-functions']):
            sel=[a for a,v in common if panel=='all-functions' or (v[1]>=8 and v[1]>=0.15*v[0])];manifest[name][panel]=dict(functions=len(sel),bytes=sum(z[1]for z in sel));save('provenance.json',manifest)
            if name=='jpeg-avx2-i386':assert sel,(name,manifest[name])
            if not sel:continue
            intervals.write_text(''.join('%d %d %d\n'%tuple(q) for q in sel))
            rows=sp.check_output([w/'census',f,intervals,str(bits)],text=True).splitlines()
            counts=sorted([(int(x.split(' ',1)[0]),x.split(' ',1)[1]) for x in rows],reverse=True)
            save('output-coverage-'+name+'-'+panel+'.json',dict(total=sum(c for c,k in counts),handled=sum(c for c,k in counts if k.startswith('hit ')),forms=counts))
            for mode in [0,1,2]:
                labels=['integer','aa','output','iced']+(['fast']if mode else [])
                def measure(lib,n):return list(map(int,sp.check_output([exe.get(lib,exe['integer']), 'capstone' if lib in exe else lib,str(mode),str(n),f,intervals,str(bits)]).split()))
                probe=measure('integer',1);rep=max(1,math.ceil(60e6/max(1,probe[0])));cycles=[]
                for i in range(15):
                    order=labels[i%len(labels):]+labels[:i%len(labels)];obs=[(k,measure(k,rep)) for k in order+order[::-1]];assert len({tuple(v[2:5])for k,v in obs})==1;assert len({tuple(v[2:])for k,v in obs if k in exe})==1
                    cycles.append(dict(ns={k:statistics.mean(v[0]/v[2] for who,v in obs if who==k) for k in labels},raw=obs))
                md=lambda a,b:statistics.median(v['ns'][a]/v['ns'][b] for v in cycles)
                row=dict(case=name,panel=panel,mode=['scan','format','detail'][mode],functions=len(sel),bytes=sum(z[1]for z in sel),repetitions=rep,gain={k:md('integer',k)for k in exe},vs_iced={k:md('iced',k)for k in exe},vs_fast={k:md('fast',k)for k in exe}if mode else {},cycles=cycles);reported.append(row);save('measurements.json',reported)
            print(name,panel,len(sel),flush=True)
    save('complete.json',dict(cases=len(reported),success=True))
w=Path(tempfile.mkdtemp(prefix='capstone-iced-formatters-'))
try:
    if hasattr(os,'sched_setaffinity'): os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    main(w)
finally:
    files=[v for v in w.rglob('*') if v.is_file()];amount=sum(v.stat().st_size for v in files);shutil.rmtree(w);save('cleanup.json',dict(removed=not w.exists(),bytes=amount,files=len(files)))
