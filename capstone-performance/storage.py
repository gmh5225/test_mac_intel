import json,math,os,platform,shlex,subprocess,statistics
import run as bench
from pathlib import Path
root,src,ev=bench.WORK,bench.SOURCE,bench.EVIDENCE
if platform.system()=='Linux':
    cores=sorted(os.sched_getaffinity(0));os.sched_setaffinity(0,{cores[0]})
    bench.write('storage-affinity.json',dict(selected=sorted(os.sched_getaffinity(0))))
t=(src/'compare.cpp').read_text()
i=t.index('static Result capstone_run(')
t=t[:i]+'extern "C" void trial_begin(csh);\nextern "C" void trial_end(csh);\n'+t[i:]
i=t.index('  if (cs_option(handle, CS_OPT_DETAIL')
t=t[:i]+'  trial_begin(handle);\n'+t[i:]
t=t.replace('cs_close(&handle);','trial_end(handle); cs_close(&handle);')
cpp=root/'storage.cpp';cpp.write_text(t)
obj=root/'storage.o'
bench.command(['clang++','-O3','-DNDEBUG','-std=c++17','-I',root/'base/include','-c',cpp,'-o',obj],'storage-driver')
iced = adapter / 'target/release/libiced_compare.a'
progs={}
for label in ['base','new']:
    build=root/(label+'-build');source=root/label
    row=next(x for x in json.loads((build/'compile_commands.json').read_text()) if x['file'].endswith('/cs.c'))
    defs=[a for a in shlex.split(row['command']) if a.startswith('-D')]
    helper=root/(label+'-lookup.o')
    bench.command(['clang','-O3','-I',source,'-I',source/'include',*defs,'-c',src/'lookup.c','-o',helper],label+'-lookup')
    exe=root/('storage-'+label)
    bench.command(['clang++',obj,helper,build/'libcapstone.a',iced,'-lpthread',*(['-ldl','-lm'] if platform.system()=='Linux' else []),'-o',exe],label+'-storage-link')
    progs[label]=exe
bench.write('storage-images.json',{k:bench.sha(p) for k,p in progs.items()})
cases=[c for c in json.loads((ev/'cases.json').read_text()) if c['consumer']=='decoder' and c['name'] in ('putty-32-0.85','scalar32','scalar64','simd64','amd64-ls') and c['mode']=='scan']
labels=['base/home','new/copy','new/home','base/copy'];rows=[]
def sample(c,label,n):
    binary,storage=label.split('/')
    env=dict(os.environ,LOOKUP_STORAGE=storage)
    return json.loads(subprocess.check_output([progs[binary],'capstone',c['mode'],str(c['selector']),str(n),c['path']],env=env))
def sig(a):return tuple(a[k] for k in ('instructions','rejected','boundary_hash','value_hash'))
for c in cases:
    n=1
    while (probe:=sample(c,labels[0],n))['cpu_ns']<10_000_000:n*=4
    reps=max(1,math.ceil(n*280_000_000/probe['cpu_ns']))
    pairs=[]
    for cycle in range(12):
        order=labels[cycle%4:]+labels[:cycle%4]
        raw=[(k,sample(c,k,reps)) for k in order+order[::-1]]
        assert len({sig(a) for _,a in raw})==1
        times={k:statistics.geometric_mean(a['cpu_ns'] for label,a in raw if label==k) for k in labels}
        pairs.append(dict(raw=raw,ratios={a+' vs '+b:times[b]/times[a] for a,b in
                      [('new/home','base/home'),('new/copy','new/home'),('base/copy','base/home'),('new/copy','base/copy')]}))
    rows.append(dict(case=c['name'],pairs=pairs))
    bench.write('storage-results.json',rows)
bench.write('measured.json',dict(complete=True))
