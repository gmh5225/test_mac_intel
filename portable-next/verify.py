from pathlib import Path
import hashlib,io,json,os,platform,shutil,subprocess as sp,tarfile,tempfile
import corpus
d=Path(__file__).resolve().parent;s=d.parent/'source';out=d.parent/'evidence';out.mkdir(exist_ok=True);profile=os.environ['SCAN_PROFILE'];q=json.loads((d/'tree.json').read_text());source=json.loads((d/'sample.json').read_text());win=os.name=='nt';t=Path(tempfile.mkdtemp())
sha=lambda raw:hashlib.sha256(raw).hexdigest()
def save(n,v):(out/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def cmd(label,argv,env=None):
    with (out/(label+'.log')).open('w')as f:z=sp.run(argv,stdout=f,stderr=sp.STDOUT,env=env)
    if z.returncode:print((out/(label+'.log')).read_text(errors='replace')[-2000:]);z.check_returncode()
def g(*args):return sp.check_output(['git','-C',s,*args],text=True).strip()
def extract(pkg):
    assert pkg[:8]==b'!<arch>\n';pos=8
    while pos+60<=len(pkg):
        head=pkg[pos:pos+60];size=int(head[48:58]);assert head[58:60]==b'\x60\n'
        if head[:16].strip().rstrip(b'/').startswith(b'data.tar'):
            with tarfile.open(fileobj=io.BytesIO(pkg[pos+60:pos+60+size]),mode='r:*')as ar:
                return {name:ar.extractfile(next(z for z in ar.getmembers() if z.isfile() and z.name.lstrip('./') in ('bin/'+name,'usr/bin/'+name))).read() for name in source['programs']}
        pos+=60+size+(size%2)
    raise ValueError('missing package member')
try:
    assert g('rev-parse','HEAD')==q['parent']
    pkg=t/'sample.deb';cmd('download',['curl','--retry','3','--retry-all-errors','-fsSL',source['url'],'-o',pkg]);data=pkg.read_bytes();assert sha(data)==source['package_sha256']
    texts={}
    for name,elf in extract(data).items():
        fields=source['programs'][name];raw=corpus.elf_text(elf);assert sha(elf)==fields['elf_sha256'] and sha(raw)==fields['section_sha256']
        text=t/(name+'.text');text.write_bytes(raw);texts[name]=text
    project=t/'project';project.mkdir();b=t/'build'
    lines=['cmake_minimum_required(VERSION 3.22)','project(RiscvRecords LANGUAGES C CXX)','enable_testing()',f'add_subdirectory("{s.as_posix()}" capstone)']
    for suffix in ('static','shared'):
        lines.extend([f'add_executable(records_{suffix} "{(d/"raw.cpp").as_posix()}")',f'target_compile_features(records_{suffix} PRIVATE cxx_std_17)',f'target_link_libraries(records_{suffix} PRIVATE capstone_{suffix})'])
    linux=platform.system()=='Linux'
    if linux and profile=='full':
        lines.extend([f'add_executable(rv_time "{(d/"riscv_options.cpp").as_posix()}")','target_compile_features(rv_time PRIVATE cxx_std_17)','target_link_libraries(rv_time PRIVATE capstone_static)','target_link_options(rv_time PRIVATE -no-pie)'])
    (project/'CMakeLists.txt').write_text('\n'.join(lines)+'\n')
    cfg=['cmake','-G','Ninja','-S',project,'-B',b,'-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_RISCV_SUPPORT=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=ON','-DCAPSTONE_BUILD_CSTEST=ON']
    chosen=os.environ.get('NATIVE_COMPILER','')
    if chosen in ('gcc','clang'):
        os.environ.update(CC=chosen,CXX='g++' if chosen=='gcc' else 'clang++')
    if chosen.startswith('gcc-'):
        os.environ.update(CC=chosen,CXX='g++-'+chosen[4:])
    if win:cfg+=['-DCMAKE_C_COMPILER=cl','-DCMAKE_CXX_COMPILER=cl','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME=ON','-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded']
    if profile=='diet':cfg.append('-DCAPSTONE_BUILD_DIET=ON')
    mixed_sources=d.parent/'neverd-config'
    verify_mixed=linux and profile=='full'
    if verify_mixed:
        expected_dev='f73475381f5bf3936bd07139142a4915f9934815'
        assert sp.check_output(['git','-C',mixed_sources,'rev-parse','HEAD'],text=True).strip()==expected_dev
        product=t/'consumer';(product/'third_party').mkdir(parents=True);(product/'third_party/capstone').symlink_to(s)
        (product/'cmake').mkdir();cm='cmake/NeverDCapstoneCompilerOptions.inc'
        shutil.copyfile(mixed_sources/cm,product/cm)
        code=(mixed_sources/'CMakeLists.txt').read_text()
        opts=code[code.index('# --- Capstone (our fork'):code.index('# --- NeverD CMake helpers')]
        (product/'CMakeLists.txt').write_text(chr(10).join(('cmake_minimum_required(VERSION 3.22)','project(Mixed LANGUAGES C CXX)',opts,'add_executable(consumer reader.cpp)','target_link_libraries(consumer PRIVATE capstone_static)','target_link_options(consumer PRIVATE -no-pie)','')))
        shutil.copyfile(d/'riscv_options.cpp',product/'reader.cpp')
    variants={};mixed={};compile_scope={}
    for stage in ('base','candidate'):
        if stage=='candidate':
            patch=t/'source.patch';patch.write_bytes(sp.check_output(['git','-C',d.parent,'cat-file','blob','HEAD:portable-next/candidate.patch']));assert sha(patch.read_bytes())==q['sha256'];g('apply','--index',str(patch));assert g('write-tree')==q['tree']
        units=['riscv_writeback_postprocess', 'riscv_mapping_index', 'riscv_scan_options', 'riscv_instruction_groups', 'riscv_op_count_iter', 'riscv_sysreg', 'riscv_reg_access', 'riscv_insn_name_segv'] if profile=='full' else ['riscv_scan_options']
        targets=['records_static','records_shared','cstool',*units]+(['rv_time'] if linux and profile=='full' else [])
        cmd('configure-'+stage,cfg);cmd('build-'+stage,['cmake','--build',b,'--parallel','4','--target',*targets])
        from csr import check
        exe,=[f for f in b.rglob('cstool') if f.is_file()]
        save('csr-'+stage,check(s,exe,stage))
        if linux and profile=='full':shutil.copyfile(b/'rv_time',t/('riscv-option-'+stage))
        if linux:
            lib,=[f for f in b.rglob('libcapstone.a') if f.is_file()]
            objs={str(f.relative_to(b)):sha(f.read_bytes()) for f in b.rglob('*.c.o') if 'CMakeFiles/capstone.dir/' in f.relative_to(b).as_posix()}
            compile_scope[stage]=dict(objects=objs,archive=sha(lib.read_bytes()))
            save('compile-scope',compile_scope)

        if linux and profile=='full':
            lib,=b.rglob('libcapstone.a')
            cmd('guard-link-'+stage,[chosen or 'cc','-std=c99','-O2','-DCAPSTONE_HAS_RISCV','-I',s,'-I',s/'include',d/'guard.c',lib,'-lm','-o',t/'guard'])
            assert sp.check_output([t/'guard'],text=True).strip()=='8448'
            save('arbitrary-arrays-'+stage,8448)
            scan=sp.check_output(['objdump','-d','--no-show-raw-insn','--disassemble=RISCV_compact_operands',b/'rv_time'],text=True)
            assert '<RISCV_compact_operands>:' in scan
            (out/('compaction-'+stage+'.asm')).write_text(scan)
        if units:cmd('units-'+stage,['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(units)+')$'])
        env=dict(os.environ)
        if win:
            dll,=[f for f in b.rglob('*.dll')if 'capstone' in f.name.lower()];env['PATH']=str(dll.parent)+os.pathsep+env['PATH']
        outputs={}
        for suffix in ('static','shared'):
            exe,=[f for f in b.rglob('records_'+suffix+('.exe'if win else'')) if f.is_file()]
            rows={}
            for name,path in texts.items():
                for opt in range(8):
                    v=list(map(int,sp.check_output([exe,'105',path,str(opt)],text=True,env=env).split()));assert v[0]>0
                    rows[name+'/'+str(opt)]=v
            outputs[suffix]=rows
        assert outputs['static']==outputs['shared']
        variants[stage]=outputs
        if verify_mixed:
            bmix=t/'mixed'
            cmd('mixed-config-'+stage,['cmake','-S',product,'-B',bmix,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON'])
            cmd('mixed-build-'+stage,['cmake','--build',bmix,'--parallel','4','--target','consumer'])
            commands=json.loads((bmix/'compile_commands.json').read_text())
            names={Path(c['file']).name for c in commands};assert {'X86Mapping.c','MipsMapping.c','PPCMapping.c','ARMMapping.c','AArch64Mapping.c','RISCVInstPrinter.c'}<=names
            assert all('CAPSTONE_RISCV_ONLY' not in row['command']for row in commands if row['file'].endswith('/RISCVInstPrinter.c'))
            objects={str(p.relative_to(bmix)):sha(p.read_bytes())for p in bmix.rglob('*.o')};lib,=bmix.rglob('libcapstone.a')
            mixed[stage]=dict(objects=objects,library=sha(lib.read_bytes()),consumer=sha((bmix/'consumer').read_bytes()))
            shutil.copyfile(bmix/'consumer',t/('mixed-'+stage))
            save('mixed-product',dict(source=q,neverd=expected_dev,stages=mixed))
    for group in (mixed,compile_scope):
        left,right=[group[k]['objects']for k in ('base','candidate')];assert left.keys()==right.keys()
        changed=[f for f in left if left[f]!=right[f]]
        assert not changed,changed
        for field in set(group['base'])-{'objects'}:
            assert group['base'][field]==group['candidate'][field],field
    photos={f:(t/f).read_bytes()==(t/g).read_bytes() for f,g in [('mixed-base','mixed-candidate'),('riscv-option-base','riscv-option-candidate')]}
    assert all(photos.values())
    save('identical-products',dict(dedicated=compile_scope['base']['archive'],mixed=mixed['base']['library'],dedicated_consumer=sha((t/'riscv-option-base').read_bytes()),mixed_consumer=mixed['base']['consumer'],dedicated_objects=len(compile_scope['base']['objects']),mixed_objects=len(mixed['base']['objects'])))
    assert variants['base']==variants['candidate'];save('complete',dict(complete=True,source=q,profile=profile,platform=platform.platform(),records=variants['candidate']['static'],programs=source['programs'],linkages=2))
finally:
    size=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);save('cleanup',dict(removed=not t.exists(),bytes=size))
