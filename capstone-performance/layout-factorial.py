from pathlib import Path
import json,os,platform,shlex,shutil,statistics as st,subprocess as sp,tempfile
import corpus,run

src=run.SOURCE

def bench(root):
    run.WORK=root
    manifest=json.loads((src/'manifest.json').read_text())
    assert run.sha(src/'candidate.patch')==manifest['source_lineage']['candidate.patch']['sha256']
    tree=run.fetch('capstone','https://github.com/NeverSight/capstone.git',manifest['capstone_revision'])
    rows=corpus.prepare(src,root,run.EVIDENCE,run.command)
    names={'putty-32-0.85','amd64-ls','scalar64','simd64','arm64-ls','mips64el-ls'}
    rows=[row for row in rows if row['name'] in names];assert len(rows)==len(names)
    run.command(['lscpu','--json'],'native-cpu')
    run.command(['clang','--version'],'compiler')
    old=(src/'single.cpp').read_text()
    i=old.index('  API() {');z=old.index('\n  }',i)
    entry='''  explicit API(const char *path) {
    library=dlopen(path, RTLD_NOW|RTLD_LOCAL);
    if (!library) throw std::runtime_error(dlerror());
'''
    for name in ['cs_open','cs_option','cs_malloc','cs_disasm_iter','cs_regs_access','cs_free','cs_close']:
        entry+='    '+name+'=reinterpret_cast<decltype('+name+')>(dlsym(library,"'+name+'")); if (!'+name+') throw std::runtime_error("'+name+'");\n'
    old=old[:i]+entry+old[z:];old=old[:old.index('int main(int argc')]+(src/'register_pair.cpp').read_text()
    (root/'pair.cpp').write_text(old);pair=root/'pair'
    run.command(['clang++','-O3','-DNDEBUG','-std=c++17','-I',tree/'include',root/'pair.cpp','-ldl','-o',pair],'compile-pair')
    arch4=['X86','ARM','AARCH64','MIPS']
    images={};summaries={}
    for version in ('base','compact'):
        if version=='compact':run.command(['git','apply',src/'candidate.patch'],'apply',tree)
        for product,arches in [('four',arch4),('seven',arch4+['RISCV','SPARC','LOONGARCH'])]:
            for flags in ('release','omit'):
                profile=product+'-'+flags;b=root/profile
                run.command(['cmake','-S',tree,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release',
                             '-DCMAKE_C_COMPILER=clang','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',
                             *['-DCAPSTONE_'+a+'_SUPPORT=ON'for a in arches],
                             *(['-DCMAKE_C_FLAGS_RELEASE=-O3 -DNDEBUG -fomit-frame-pointer -Wno-error=incompatible-pointer-types-discards-qualifiers']if flags=='omit'else []),
                             '-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF'],
                            'configure-'+profile+'-'+version)
                run.command(['cmake','--build',b,'--target','capstone_shared','--parallel','4'],'build-'+profile+'-'+version)
                obj={str(f.relative_to(b)):run.sha(f)for f in (b/'CMakeFiles/capstone.dir').rglob('*.o')}
                binary=root/(profile+'-'+version+'.so');shutil.copyfile(b/'libcapstone.so',binary)
                twin=root/('aa-'+binary.name);shutil.copyfile(binary,twin)
                assert run.sha(binary)==run.sha(twin)
                images[profile,version]=(binary,twin)
                summaries[profile+'-'+version]={'objects':obj,'library':run.sha(binary),'arguments':shlex.split(json.loads((b/'compile_commands.json').read_text())[0]['command'])}
    run.write('images.json',summaries)
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    profiles={};seen={};records=[]
    # Skip timing a flag spelling only when every object and linked library
    # are byte-identical on both sides. Record the verified equivalence.
    for profile in ('four-omit','seven-release','four-release','seven-omit'):
        identity=tuple(summaries[profile+'-'+v]['library'] for v in ('base','compact'))
        if identity in seen:
            previous=seen[identity]
            assert all(summaries[profile+'-'+v]['objects']==summaries[previous+'-'+v]['objects']for v in ('base','compact'))
            profiles[profile]={'identical_to':previous}
        else:
            seen[identity]=profile;profiles[profile]={'timed':True}
    run.write('profiles.json',profiles)
    for row in rows:
        for mode in (1,2):
            for profile,v in profiles.items():
                if 'timed' not in v:continue
                b,ba=images[profile,'base'];c,ca=images[profile,'compact']
                record=dict(profile=profile,case=row['name'],mode=('scan','format','detail')[mode],plans={})
                for start,other,label in [(b,c,'forward'),(c,b,'reverse'),(b,ba,'base-aa'),(c,ca,'new-aa')]:
                    raw=json.loads(sp.check_output([pair,start,other,str(row['selector']),str(mode),row['path']],text=True))
                    assert len(raw['ticks'])==9
                    ratios=[sum(t[::2])/sum(t[1::2]) if i%2==0 else sum(t[1::2])/sum(t[::2]) for i,t in enumerate(raw['ticks'])]
                    if label=='reverse':ratios=[1/x for x in ratios]
                    record['plans'][label]=dict(raw=raw,pairs=ratios,median=st.median(ratios))
                record['median']=st.median(record['plans']['forward']['pairs']+record['plans']['reverse']['pairs'])
                records.append(record);run.write('measurements.json',records)
    assert len(records)==len(seen)*len(names)*2
if __name__=='__main__':
    run.EVIDENCE.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=os.environ['RUNNER_TEMP']) as tmp:
        try:bench(Path(tmp))
        finally:
            n=sum(v.stat().st_size for v in Path(tmp).rglob('*')if v.is_file());shutil.rmtree(tmp)
            run.write('cleanup.json',dict(bytes=n,removed=True))
