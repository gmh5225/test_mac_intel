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
    reference='729680277dd762704ea3270291b7a75318f51583'
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
    save('variants.json',dict(control='byte-identical baseline copy',integer='Released four-backend Capstone, revision '+reference,aa='byte-identical reference',scan='R1121 isolated complete VEX32 output; released scan unchanged',iced='NeverSight iced IntelFormatter',fast='NeverSight iced FastFormatter'))
    save('entrypoints.json',dict(scan='cs_disasm_iter',format='X86_disasmIter',detail='X86_disasmIter',consumer='Decoder::decodePhysical via X86_disasmIter, NeverD dev ddf30e5255af3aa7fa071d756ada080c4c957071'))
    inc=(r/'driver.cpp').read_text().replace('size_t iced_trace(const','size_t iced_trace(unsigned, const').replace('if(argc!=6)','if(argc!=7)').replace('  csh handle=0;','  unsigned bits=std::stoul(argv[6]);\n  csh handle=0;').replace('cs_open(CS_ARCH_X86,CS_MODE_64,','cs_open(CS_ARCH_X86,bits==32?CS_MODE_32:CS_MODE_64,').replace('iced_create(64,mode)','iced_create(bits,mode)').replace('iced_trace(ptr,','iced_trace(bits,ptr,')
    inc=inc.replace('iced_create(bits,mode)','iced_create(bits,mode | (engine=="fast" ? 8 : 0))').replace('engine!="capstone" && engine!="iced"','engine!="capstone" && engine!="iced" && engine!="fast"')
    inc=inc.replace('if (mode>2 ||','if (mode>4 ||').replace('mode==2 ? CS_OPT_ON','mode>=2 ? CS_OPT_ON')
    inc=inc.replace('if (mode == 2) {','if (mode == 2 || mode == 4) {\n        if (mode == 2) {').replace('        const auto &x = insn->detail->x86;', '        }\n        const auto &x = insn->detail->x86;')
    old_engine='std::string engine=argv[1];';assert inc.count(old_engine)==1
    inc=inc.replace(old_engine,old_engine+'\n  if(engine=="iced____") engine="iced"; else if(engine=="fast____") engine="fast";')
    assert inc.count('iced_trace(bits,ptr,')==1
    (w/'functions.cpp').write_text(inc);run(['clang++','-O3','-DNDEBUG','-std=c++17','-I',base/'include','-c',w/'functions.cpp','-o',w/'driver.o'],'driver')
    profile=['-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+os.environ['CC'],'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',*['-DCAPSTONE_'+arch+'_SUPPORT=ON' for arch in ['X86','ARM','AARCH64','MIPS']],'-DCMAKE_C_FLAGS_RELEASE=-O3 -DNDEBUG -fomit-frame-pointer '+('-Wno-error=discarded-qualifiers' if os.environ['CC']=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),'-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_SHARED_LIBS=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF']
    tree=w/'tree';run(['git','clone','-q','--shared','--no-checkout',base,tree],'capstone-clone');run(['git','checkout','-q','--detach',reference],'capstone-checkout',tree);b=w/'build';run(['cmake','-S',tree,'-B',b,*profile],'configure');evidence={};exe={}
    objects={}
    for label in ('integer','aa','scan'):
        if label=='aa':
            exe[label]=w/'baseline-copy';shutil.copy2(exe['integer'],exe[label]);continue
        patches=[] if label=='integer' else [r/('dispatch.patch' if label=='output' else 'scan.patch')]
        for patch in patches: run(['git','apply',patch],'apply-'+label+'-'+patch.stem,tree)
        run(['cmake','--build',b,'--target','capstone_static','--parallel','4'],'build-'+label)
        objroot=b/'CMakeFiles/capstone.dir'
        objects[label]={str(path.relative_to(objroot)):sha(path) for path in objroot.rglob('*.o')}
        assert len(objects[label])>30
        if label in ('output','scan'):
            changed={n for n in objects['integer']if objects[label].get(n)!=objects['integer'][n]}
            added=set(objects[label])-set(objects['integer'])
            assert added==set(),added
            expected={'arch/X86/X86VectorOutput.c.o'} if label=='output' else {'arch/X86/X86VectorOutput.c.o'}
            assert changed==expected,(label,changed,expected)
            save('objects-'+label+'.json',dict(changed=sorted(changed),added=sorted(added),total=len(objects[label])))
        for component in ('X86VectorOutput','X86DisassemblerDecoder'):
            object_file=objroot/'arch/X86'/(component+'.c.o')
            assembly=sp.check_output(['objdump','-dr',object_file])
            with gzip.open(p/'evidence'/(label+'-'+component+'.asm.gz'),'wb') as stream:
                stream.write(assembly)
        code=inc.replace('#include <capstone/capstone.h>','#include <capstone/capstone.h>\n#include "X86ScanAdapter.h"');old='bool ok = cs_disasm_iter(handle, &cursor, &left, &ip, insn);';assert code.count(old)==1;code=code.replace(old,'bool ok = mode ? X86_disasmIter(handle,&cursor,&left,&ip,insn) : cs_disasm_iter(handle,&cursor,&left,&ip,insn);');(w/'owned.cpp').write_text(code);obj=w/'owned.o';run(['clang++','-O3','-DNDEBUG','-std=c++17','-I',base/'include','-I',tree/'arch/X86','-c',w/'owned.cpp','-o',obj],'owned-driver-'+label)
        target=w/('run-'+label);run(['clang++',obj,b/'libcapstone.a',ad/'target/release/libiced_compare.a','-lpthread','-ldl','-lm','-o',target],'link-'+label);exe[label]=target
        (p/'evidence'/(label+'-symbols.txt')).write_bytes(sp.check_output(['nm','-n','-S','--defined-only',target]))
        (p/'evidence'/(label+'-sections.txt')).write_bytes(sp.check_output(['readelf','-WS',target]))

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
    save('launch-controls.json',dict(launches=launches,aslr_disable_returncode=probe.returncode,aslr_disable_stderr=probe.stderr,original_sha256={k:hashlib.sha256(v).hexdigest()for k,v in payloads.items()},padded_sha256={k:hashlib.sha256(v).hexdigest()for k,v in padded.items()},image_inode=image_inode,fixed_size=maximum,equal_length_engine_selectors=True,purpose='Qualify R1121 original and controlled launches; retain all earlier prototype regressions separately.'))
    run(['git','apply',r/'scan.patch'],'apply-census',tree)
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
                cycles={launch:[]for launch in launches};labels=['integer','aa','scan','iced']+(['fast'] if mode else [])
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
                    row['vs_iced']=md('iced','scan')
                    row['vs_fast']=md('fast','scan') if mode else None
                    reported.append(row)
                save('measurements.json',reported)
            print(name,panel,len(sel),flush=True)
    save('complete.json',dict(cases=len(reported),success=True,native_qualification=False,controlled_replication=True,launches=launches))
w=Path(tempfile.mkdtemp(prefix='capstone-iced-formatters-'))
try:
    if hasattr(os,'sched_setaffinity'): os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    main(w)
finally:
    files=[v for v in w.rglob('*') if v.is_file()];amount=sum(v.stat().st_size for v in files);shutil.rmtree(w);save('cleanup.json',dict(removed=not w.exists(),bytes=amount,files=len(files)))
