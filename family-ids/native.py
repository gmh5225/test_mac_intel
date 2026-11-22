from pathlib import Path
import hashlib, json, os, platform, shutil, subprocess as sp, sys, tempfile
r=Path(__file__).resolve().parent
src=r.parent/'source';out=r.parent/'evidence';out.mkdir(exist_ok=True)
load=lambda f: json.loads(f.read_text())
def save(name, obj): (out/(name+'.json')).write_text(json.dumps(obj,indent=2)+'\n')
def sha(raw):return hashlib.sha256(raw).hexdigest()
def git(*args):return sp.check_output(['git','-C',src,*args],text=True).strip()
def run(name,args):
    with (out/(name+'.log')).open('w') as f: z=sp.run(args,stdout=f,stderr=sp.STDOUT)
    if z.returncode: print((out/(name+'.log')).read_text(errors='replace')[-3500:],flush=True);z.check_returncode()
q=load(r/'tree.json');layers=load(r/'layers.json')
assert git('rev-parse','HEAD')==layers['base_commit'] and sha((r/'writer.patch').read_bytes())==q['sha256']
cc=os.environ['CC']
if cc=='clang' and platform.machine()=='x86_64':run('prod-identity',[sys.executable,'-B',r/'check.py'])
git('apply','--index',str(r/'headers.patch'))
assert git('write-tree')==layers['layers']['base']['rebased']
profiles={'full':[], 'no-att':['-DCAPSTONE_X86_ATT_DISABLE=ON'], 'reduced':['-DCAPSTONE_X86_REDUCE=ON'], 'diet':['-DCAPSTONE_BUILD_DIET=ON']}
builds=Path(tempfile.mkdtemp());members={};images={};units={}
try:
    for stage in ('before','after'):
        if stage=='after':
            git('apply','--index',str(r/'writer.patch'));assert git('write-tree')==q['tree']
        for profile,opts in profiles.items():
            b=builds/profile
            active=profile in ('full','no-att')
            tests=['x86_scan_batch','text_option','detail_option']
            if active: tests+=['x86_simple_output','x86_evex_detail','x86_buffer_bounds','x86_reg_access']
            if stage=='before':
                run('configure-'+profile,['cmake','-G','Ninja','-S',src,'-B',b,'-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_X86_NEAR_INDIRECT_OUTPUT=ON',*opts])
            run('build-'+stage+'-'+profile,['cmake','--build',b,'--target','capstone_static','capstone_shared',*tests,'--parallel','4'])
            run('unit-'+stage+'-'+profile,['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','--parallel','4','-R','^unit_('+'|'.join(tests)+')$'])
            lib=b/'libcapstone.a';so,=[v for v in b.glob('libcapstone.so.*')if not v.is_symlink()]
            names=sp.check_output(['ar','t',lib],text=True).splitlines()
            members.setdefault(profile,{})[stage]={n:sha(sp.check_output(['ar','p',lib,n])) for n in names}
            images.setdefault(profile,{})[stage]=sha(so.read_bytes())
            assert len(names)==len(members[profile][stage])>=20
            units.setdefault(profile,{})[stage]=tests
            if stage=='after' and active:
                run('gen-build-'+profile,['c++','-std=c++17','-O2','-I',src/'include',src/'suite/synctools/x86_simple_output.cpp',lib,'-o',builds/'generate'])
                z=sp.run([builds/'generate','--cmov64'],capture_output=True,check=True)
                g=src/'arch/X86/X86GenCmov64Output.inc'
                assert z.stdout==g.read_bytes() and z.stdout.count(b'UINT64_C')==32
                (out/('canonical-'+profile+'.log')).write_bytes(z.stderr)
    changed={}
    for prof,row in members.items():
        a,b=row['before'],row['after'];assert a.keys()==b.keys() and images[prof]['before']==images[prof]['after'],prof
        changed[prof]=[n for n in a if a[n]!=b[n]]
        if prof in ('diet','reduced'):assert not changed[prof],(prof,changed[prof])
        else: assert 'X86Sse64Output.c.o' in changed[prof] and set(changed[prof])<= {'X86Sse64Output.c.o','X86Vex32Output.c.o'},(prof,changed[prof])
    save('configurations',dict(complete=True,source=q,layers=layers,members=members,images=images,changed=changed,units=units,host=platform.platform(),cc=sp.check_output([cc,'--version'],text=True).splitlines()[0]))
finally:
    size=sum(v.stat().st_size for v in builds.rglob('*')if v.is_file()and not v.is_symlink());shutil.rmtree(builds);save('cleanup',dict(removed=not builds.exists(),bytes=size))
