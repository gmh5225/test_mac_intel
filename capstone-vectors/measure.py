from pathlib import Path
import hashlib,itertools,json,math,os,platform,random,shutil,statistics,subprocess as sp,sys,tempfile
r=Path(__file__).resolve().parent;p=r.parent
e=p/'evidence';e.mkdir(exist_ok=True);rd=lambda f:json.loads(f.read_text())
q=rd(r/'tree.json');m=rd(r/'experiment.json');dev=m['neverd'];base=p/'source';root=p/'neverd-config';ice=p/'iced-source'
def save(name,value):
    f=e/(name+'.json');temp=f.with_suffix('.tmp');temp.write_text(json.dumps(value,indent=2)+'\n');temp.replace(f)
def get(*args,**kwargs):return sp.check_output(args,text=True,**kwargs)
def run(*args,**kwargs):sp.run(args,check=True,**kwargs)
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def interval(values):
    x=sorted(values);n=len(x)
    def rank(q):
        return next(k for k in range(1,n+1) if 40*sum(math.comb(n,i)*k**i*(n-k)**(n-i) for i in range(n//2+1,n+1))>=q*n**n)-1
    return [statistics.median(x),x[rank(1)],x[rank(39)]]
w=Path(tempfile.mkdtemp());project=w/'project';build=w/'build';ad=w/'adapter'
try:
    assert get('git','-C',base,'rev-parse','HEAD').strip()==m['checkout_commit'] and get('git','-C',base,'write-tree').strip()==m['checkout_tree']
    assert get('git','-C',root,'rev-parse','HEAD').strip()==dev
    assert get('git','-C',ice,'rev-parse','HEAD').strip()==m['iced_revision']
    assert all(sha(r/f)==v for f,v in m['drivers'].items())
    (project/'third_party').mkdir(parents=True);(project/'third_party/capstone').symlink_to(base)
    (project/'cmake').mkdir();cm='cmake/NeverDCapstoneCompilerOptions.inc'
    (project/cm).write_bytes(sp.check_output(['git','-C',root,'show',dev+':'+cm]))
    v=get('git','-C',root,'show',dev+':CMakeLists.txt')
    (project/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(Layers LANGUAGES C CXX)\n'+v[v.index('# --- Capstone (our fork'):v.index('# --- NeverD CMake helpers')])
    run('cmake','-G','Ninja','-S',project,'-B',build,'-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON')
    run('cmake','--build',build,'--target','capstone_static','--parallel','4');lib,=build.rglob('libcapstone.a')
    files={Path(c['file']).name for c in rd(build/'compile_commands.json')};assert {'MipsMapping.c','AArch64Mapping.c','ARMMapping.c','X86Sse64Output.c'}<=files and 'X86PublicOutput.c' not in files
    ad.mkdir()
    for f in ('Cargo.lock','iced.rs'):shutil.copyfile(r/f,ad/f)
    (ad/'Cargo.toml').write_text((r/'Cargo.toml').read_text().replace('ICED_ROOT',str(ice)))
    run('cargo','build','--release','--locked',cwd=ad)
    ice_lib=ad/'target/release/libiced_compare.a'
    shutil.copyfile(r/'driver.cpp',w/'driver.cpp')
    flags=['-lpthread','-lm']+(['-framework','Security','-framework','CoreFoundation','-liconv']if sys.platform=='darwin'else['-ldl','-no-pie'])
    run('clang++','-O3','-DNDEBUG','-std=c++17','-I',base,'-I',base/'include','-c',w/'driver.cpp','-o',w/'driver.o')
    lines=(w/'driver.cpp').read_text().splitlines()
    keep=[line for line in lines if '(void)batch_span<true,X86_scanNativeBatch>' not in line and 'else if(engine=="private"' not in line]
    assert len(keep)==len(lines)-3
    (w/'public-only.cpp').write_text('\n'.join(keep)+'\n')
    run('clang++','-O3','-DNDEBUG','-std=c++17','-I',base,'-I',base/'include','-c',w/'public-only.cpp','-o',w/'public-only.o')
    assert 'X86_' not in get('nm','-u',w/'public-only.o')
    for f in ('frozen_deb.py','jpeg_archive.py','pe_panels.py','pdata.py','pe-images.json','inputs.json','vectors.cpp','libmvec.py','libmvec.json'):shutil.copyfile(r/f,w/f)
    images={}
    maps=rd(r/'source.json')
    assert maps['prefix']==q and maps['base']['commit']==q['patch_base']
    layout={}
    from elftools.elf.elffile import ELFFile
    for stem in ('real','states','guard'):
        run('clang++','-O2','-std=c++17','-I',base/'include',r/('trial-'+stem+'.cpp'),'-ldl','-o',w/('trial-'+stem))
    from training import fetch
    from foreign_time import measure as time_foreign
    samples=rd(r/'ppc-samples.json')['fixtures'];training=rd(r/'training.json');origin,=(z for z in training if z['arch']=='ppc64el')
    extra=[dict(origin,name=n,command=n.split('-',1)[1],text_sha256=v['sha256'])for n,v in samples.items()if n!=origin['name']]
    docs=w/'corpus-config';docs.mkdir();(docs/'training.json').write_text(json.dumps(training+extra));all_rows=fetch(docs,w)
    foreign_rows=all_rows[:len(training)];save('foreign-corpus',all_rows)
    for row in all_rows:
        if row['arch']=='ppc64el':assert samples[row['name']]['sha256']==row['text_sha256'] and samples[row['name']]['package']==row['package_sha256']
    run('clang++','-O3','-std=c++17','-I',base/'include','-c',r/'foreign.cpp','-o',w/'foreign.o')
    marker=w/'native-reference.c'
    marker.write_text('#include "arch/X86/X86ScanAdapter.h"\n__attribute__((used)) static __typeof__(&X86_disasmIterText) const native_reader = X86_disasmIterText;\n')
    run('clang','-O2','-I',base,'-I',base/'include','-c',marker,'-o',w/'native-reference.o')
    assert 'X86_disasmIterText' in get('nm','-u',w/'native-reference.o')
    from product_layout import all_functions
    from fixed_image import FixedImage
    arch=os.uname().machine;exe_layout={};symbols={};products={};routes=('native','ordinary','foreign','foreign-only')
    for label in ('shipping','production','forward','canonical'):
        if label=='production':
            patch=r/'candidate.patch';assert sha(patch)==q['sha256']
            run('git','-C',base,'apply','--index',patch);assert get('git','-C',base,'write-tree').strip()==q['tree']
            run('cmake','--build',build,'--target','capstone_static','--parallel','4')
            run('clang++','-O2','-std=c++17','-I',base,'-I',base/'include',r/'unary-guard.cpp',lib,'-o',w/'unary-guard')
            guard=list(map(int,get(w/'unary-guard').split()));assert guard[:2]==[14647296,8891200];save('guard',guard)
        if label=='forward':
            # Rename only the undefined symbol in the archive member which calls it.
            member='X86VectorFallback64.c.o'
            assert get('ar','t',lib).splitlines().count(member)==1
            unit=w/member;unit.write_bytes(sp.check_output(['ar','p',lib,member]))
            symbol='X86_decodeGroup64OrFull'
            assert symbol in get('nm','-u',unit).split()
            run('objcopy','--redefine-sym',symbol+'=X86_benchmarkGroupCall',unit)
            assert 'X86_benchmarkGroupCall' in get('nm','-u',unit).split()
            run('ar','rD',lib,unit)
            assert get('ar','t',lib).splitlines().count(member)==1
        link=[]
        if label in ('forward','canonical'):
            # Force the archive member in both links. The two calls use the same internal convention.
            target='X86_decodeGroup64OrFull' if label=='forward' else 'cs_decode_full_insn'
            link=['-Wl,-u,X86_decodeGroup64OrFull','-Wl,-u,cs_decode_full_insn']
        args={'native':([w/'driver.o'],[ice_lib,*flags]),'ordinary':([w/'public-only.o'],[ice_lib,*flags]),'foreign':([w/'foreign.o',w/'native-reference.o'],['-no-pie']),'foreign-only':([w/'foreign.o'],['-no-pie'])}
        exe_layout[label]={};symbols[label]={};products[label]={}
        for route in routes:
            objects,ld=args[route];exe=w/(route+'-'+label)
            alias=['-Wl,--defsym,X86_benchmarkGroupCall='+target] if label in ('forward','canonical') and route in ('native','foreign') else []
            run('clang++',*objects,*(link if route in ('native','foreign') else []),lib,*ld,*alias,'-o',exe)
            symbols[label][route]=all_functions(exe);symbols[label][route].pop('X86_benchmarkGroupCall',None)
            with exe.open('rb')as f:
                elf=ELFFile(f)
                exe_layout[label][route]={v.name:[v['sh_addr'],v['sh_size'],hashlib.sha256(v.data()).hexdigest()]for v in elf.iter_sections()if v['sh_flags']&2 and v['sh_type']!='SHT_NOBITS'}
            products[label][route]=sha(exe)
    diffs={}
    for route in routes:
        a,b=(symbols[t][route] for t in ('canonical','forward'));same_addresses=set(a)==set(b) and all([n[:2]for n in v]==[n[:2]for n in b[k]]for k,v in a.items())
        changed=[k for k in sorted(set(a)|set(b))if a.get(k)!=b.get(k)]
        reloc={k for k in exe_layout['canonical'][route]if exe_layout['canonical'][route][k][:2]!=exe_layout['forward'][route][k][:2]}
        sections=[k for k in exe_layout['canonical'][route]if exe_layout['canonical'][route][k]!=exe_layout['forward'][route][k]]
        original=symbols['shipping'][route]
        vs_original=sorted(k for k in set(a)|set(original)if a.get(k)!=original.get(k))
        diffs[route]=dict(total=len(a),same_addresses=same_addresses,changed=changed,reloc=list(reloc),sections=sections,versus_shipping=len(vs_original),examples=vs_original[:20])
        save('links',dict(diffs=diffs,sections=exe_layout,hashes=products))
        if route in ('ordinary','foreign-only'):
            # Neither consumer has any reference to the AMD64 native member.
            assert all(products[t][route]==products['shipping'][route] for t in products)
        else:
            assert same_addresses and not reloc and changed==['X86_decodeOutputMiss64'],(route,diffs[route])
            assert set(sections)<={'.cs_x86_vector_fallback64_text','.note.gnu.build-id'}
        prod=symbols['production'][route]
        shifts={}
        for name in ('X86_disasmIterText','X86_disasmIter32','tryOutput32','X86_decodeOutputMiss32','X86_decodeRegisterFallback32','X86_decodeOutputMiss64','cs_decode_full_insn','cs_disasm_iter','Mips_getInstruction'):
            if name in original:
                assert name in prod and len(original[name])==len(prod[name])
                shifts[name]=[[x[0],y[0]-x[0],x[1],y[1],x[2]==y[2]] for x,y in zip(original[name],prod[name])]
        diffs[route]['shipping_to_production']=shifts
        save('links',dict(diffs=diffs,sections=exe_layout,hashes=products))
    import pe_panels
    fixtures={}
    for name,bits,f,spans,_ in pe_panels.prepare(w):
        if name not in ('putty-32-0.85','putty-64-0.85'):continue
        spec=m['provenance'][name];assert sha(f)==spec['text_sha256']
        selected=[s for s in spans if tuple(s)not in {tuple(a[:3])for a in spec['excluded_incompatible_extents']}]
        path=w/(name+'.tsv');path.write_text(''.join('%d %d %d\n'%tuple(a)for a in selected));assert sha(path)==spec['extent_sha256'];fixtures[name]=(str(bits),f,path)
    run(sys.executable,'-B',w/'libmvec.py');vec=rd(w/'libmvec.json');name='libmvec-amd64';f=w/'libmvec.text';p=w/(name+'.tsv');p.write_text('0 %d %d\n'%(vec['bytes'],vec['address']));spec=m['provenance'][name]
    assert sha(f)==spec['text_sha256'] and sha(p)==spec['extent_sha256'];fixtures[name]=('64',f,p)
    assert len(fixtures)==3
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))});result={};receipts={}
    for route in routes:
        if route in ('ordinary','foreign-only'):continue
        sources={t:(w/(route+'-'+tag)).read_bytes() for t,tag in [('shipping','shipping'),('base','canonical'),('candidate','forward'),('production','production')]}
        image=FixedImage(w/('selected-'+route),sources,True);tasks=[]
        if route in ('native','ordinary'):
            for name,(bits,path,ranges) in fixtures.items():
                for engine in (('private','capstone') if route=='native'else ('capstone',)):
                    for mode in range(3):
                        def command(n,e=engine,m=mode,f=path,s=ranges,b=bits):return [e,str(m),str(n),f,s,b]
                        tasks.append((name+'/'+engine+'/'+str(mode),command))
        else:
            for row in foreign_rows:
                if row['arch']not in ('arm','aarch64','arm64','mips64el','ppc64el','riscv64'):continue
                for mode in range(3):
                    def command(n,z=row,m=mode):return [z['arch'],w/(z['name']+'.text'),str(m),str(n)]
                    tasks.append((row['name']+'/'+str(mode),command))
        for key,cmd in tasks:
            def take(label,n):
                image.select(label)
                return list(map(int,get('setarch',arch,'-R',image.path,*cmd(n)).split()))
            reps=max(1,math.ceil(22e6/take('base',1)[0]));expected=take('base',reps)[2:];assert expected[0]>0
            labels=['shipping','base','candidate','copy','repeat','production'];rng=random.Random(route+key);cycles=[]
            for _ in range(17):
                rng.shuffle(labels);block={k:[] for k in labels}
                for label in labels+labels[::-1]:
                    z=take(label,reps);assert z[2:]==expected;block[label].append(z[:2])
                cycles.append({k:[sum(x[i]for x in v)for i in (0,1)]for k,v in block.items()})
            result[route+'/'+key]=dict(reps=reps,checks=expected,blocks=cycles);save('timings',result)
        receipts[route]=image.receipt()
    save('complete',dict(complete=True,run_source=maps,isa=arch,panels=len(result),images=receipts))

finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
