from pathlib import Path
import hashlib,itertools,json,os,platform,shutil,subprocess as sp,sys,tempfile
r=Path(__file__).resolve().parent;p=r.parent;out=p/'evidence';out.mkdir(exist_ok=True)
rd=lambda f:json.loads(f.read_text())
def save(name,x):(out/(name+'.json')).write_text(json.dumps(x,indent=2)+'\n')
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def run(*args):sp.run(args,check=True)
def get(*args):return sp.check_output(args,text=True)
def once(s,a,b):assert s.count(a)==1,a;return s.replace(a,b)
m=rd(r/'experiment.json');cap=p/'source';nd=p/'neverd-config'
assert get('git','-C',cap,'rev-parse','HEAD').strip()==m['checkout_commit'] and get('git','-C',cap,'write-tree').strip()==m['checkout_tree']
assert get('git','-C',nd,'rev-parse','HEAD').strip()==m['neverd']
w=Path(tempfile.mkdtemp())
try:
    proj=w/'project';b=w/'build';(proj/'cmake').mkdir(parents=True);(proj/'third_party').mkdir()
    (proj/'third_party/capstone').symlink_to(cap)
    cm='cmake/NeverDCapstoneCompilerOptions.inc';shutil.copyfile(nd/cm,proj/cm)
    s=(nd/'CMakeLists.txt').read_text()
    (proj/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(StageCounts LANGUAGES C CXX)\n'+s[s.index('# --- Capstone (our fork'):s.index('# --- NeverD CMake helpers')])
    run('cmake','-S',proj,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON')
    for variant in ('original','counted'):
        if variant=='counted':
            f=cap/'cs.c';code=once(f.read_text(),'static inline void fill_insn(', 'extern uint64_t profile_stage[4];\n\nstatic inline void fill_insn(')
            code=once(code,'\tSStream_trimls(OS);','\t++profile_stage[1];\n\tprofile_stage[2] += stream_length_valid;\n\tSStream_trimls(OS);')
            marker='\tif (!handle->disasm((csh)(uintptr_t)handle, code, size, &mci, insn_size,'
            code=once(code,marker,'\t++profile_stage[0];\n'+marker)
            marker='if (request == CS_RECORD_PUBLIC_ITER && !handle->no_text) {'
            f.write_text(once(code,marker,marker+'\n\t\t\t++profile_stage[3];'))
        run('cmake','--build',b,'--target','capstone_static','--parallel','4');archive,=b.rglob('libcapstone.a')
        run('clang++','-O2','-std=c++17','-I',cap,'-I',cap/'include',r/'census.cpp',archive,'-o',w/variant)
        if variant=='original':
            commands=rd(b/'compile_commands.json');names={Path(v['file']).name for v in commands}
            assert {'ARMMapping.c','X86Sse64Output.c','PPCMapping.c','RISCVMapping.c','AArch64InstPrinter.c','MipsMapping.c'}<=names and 'X86PublicOutput.c' not in names
            public_fixed='CAPSTONE_STATIC_X86_READERS' in next(v['command']for v in commands if Path(v['file']).name=='cs.c')
            run('clang++','-O2','-std=c++17','-I',cap/'include',r/'vectors.cpp',archive,'-o',w/'vectors')
    for f in ('frozen_deb.py','jpeg_archive.py','pe_panels.py','pdata.py','pe-images.json','inputs.json','libmvec.py','libmvec.json'):shutil.copyfile(r/f,w/f)
    inputs=rd(w/'inputs.json');(w/'inputs.json').write_text(json.dumps({k:v for k,v in inputs.items()if k in m['samples']}))
    sys.path.insert(0,str(w));import pe_panels,frozen_deb
    run(sys.executable,'-B',w/'libmvec.py');v=rd(w/'libmvec.json')
    report={};hist={}
    for name,bits,image,spans,_ in itertools.chain([('libmvec-amd64',64,w/'libmvec.text',[(0,v['bytes'],v['address'])],v)],pe_panels.prepare(w),frozen_deb.prepare(w)):
        spec=m['provenance'][name];assert sha(image)==spec['text_sha256'] and len(spans)==spec['input_functions']
        selected=[z for z in spans if tuple(z) not in {tuple(j[:3])for j in spec['excluded_incompatible_extents']}]
        ext=w/(name+'.tsv')
        def emit():ext.write_text(''.join('%d %d %d\n'%tuple(z)for z in selected))
        emit()
        if m['samples'][name]=='simd-functions':
            select=[list(map(int,z.split()))for z in get(w/'vectors',str(bits),image,ext).splitlines()]
            assert len(select)==len(selected);selected=[z for z,a in zip(selected,select)if a[1]>=8 and a[1]>=.15*a[0]];emit()
        assert sha(ext)==spec['extent_sha256'] and len(selected)==spec['timed_functions']
        baseline=None
        for variant in ('original','counted'):
            lines=get(w/variant,image,ext,str(bits)).splitlines()
            totals=list(map(int,lines[0].split('\t')[1:]));rows=[list(map(int,line.split('\t')[1:])) for line in lines[1:5]]
            assert all(line.startswith('reader\t') for line in lines[1:5]) and all(len(row)==9 for row in rows)
            families={x[1]:list(map(int,x[2:]))for line in lines[5:] if (x:=line.split('\t'))[0]=='family'}
            stable=[totals,[x[0] for x in rows],{k:v[0]for k,v in families.items()}]
            assert sum(z[0]for z in families.values())==totals[0] and totals[2]==spec['bytes']
            if variant=='original':
                assert all(not any(z[1:])for z in rows);baseline=stable
            else:
                assert stable==baseline,(name,totals,baseline[:2])
                assert all(row[1]==row[2] and 0<=row[3]<=row[2]<=totals[0] and 0<=row[4]<=totals[0] for row in rows)
                assert all(sum(z[1+i] for z in families.values())==rows[i][1] for i in range(4))
                report[name]=dict(totals=totals,extent_sha256=sha(ext),rows=rows,text_sha256=sha(image));hist[name]=families
    assert set(report)==set(m['samples'])
    save('histogram',hist);save('observations',report)
    save('complete',dict(complete=True,capstone=m['checkout_commit'],neverd=m['neverd'],probe=sha(r/'census.cpp'),compiler=get('clang','--version').splitlines()[0],host=platform.platform(),public_fixed=public_fixed,reader_order=['public text','public detail','private text','private detail'],columns=['semantic digest','generic decode','stream split','known stream length','fixed-record entry','generic mnemonic bytes','generic operand bytes','generic explicit operands','rejected generic decode'],totals=['accepted','rejected','covered bytes','boundary digest','text cross-reader differences','detail cross-reader differences']))
finally:
    n=sum(f.stat().st_size for f in w.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
