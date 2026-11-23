from pathlib import Path
from math import ceil,comb
import hashlib,json,os,platform,random,shutil,statistics,subprocess as sp,sys,tempfile
r=Path(__file__).resolve().parent;s=r.parent/'source';e=r.parent/'evidence';e.mkdir(exist_ok=True)
rd=lambda f:json.loads(f.read_text());q=rd(r/'tree.json');samples=rd(r/'samples.json');ref=rd(r/'firmware-reference.json')
def put(n,z):(e/(n+'.json')).write_text(json.dumps(z,indent=2)+'\n')
def call(*args):return sp.check_output(args,text=True).strip()
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run(*args):sp.run(args,check=True)
def interval(v):
    n=len(v);m=n//2+1;v=sorted(v)
    def threshold(bound):
        return next(i-1 for i in range(1,n+1)if 40*sum(comb(n,j)*i**j*(n-i)**(n-j)for j in range(m,n+1))>=bound*n**n)
    return dict(median=statistics.median(v),ci95=[v[threshold(1)],v[threshold(39)]])
t=Path(tempfile.mkdtemp());b=t/'build'
try:
    run(sys.executable,'-B',r/'fetch.py');assert rd(r/'samples.json')==samples
    assert call('git','-C',s,'rev-parse','HEAD')==q['parent']; assert sha(r/'candidate.patch')==q['sha256']
    if sys.platform.startswith('linux'):os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    source={};rows={};result={};keys=['base','copy','candidate']
    for k in ('base','candidate'):
        if k=='candidate':
            run('git','-C',s,'apply','--index',r/'candidate.patch');assert call('git','-C',s,'write-tree')==q['tree']
            run(sys.executable,'-B',s/'suite/synctools/xcore_literal_operands.py','--check')
        run('cmake','-G','Ninja','-S',s,'-B',b,'-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_CSTEST=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_XCORE_SUPPORT=ON')
        run('cmake','--build',b,'--parallel','3','--target','capstone_static')
        for name in ('time','firmware'):
            run('clang','-D_POSIX_C_SOURCE=200809L','-std=c11','-O3','-I',s/'include',r/(name+'.c'),b/'libcapstone.a','-o',t/(k+name))
        source[k]=dict(tree=call('git','-C',s,'write-tree'),lib=sha(b/'libcapstone.a'),bin=sha(t/(k+'time')))
    assert source['base']['lib']!=source['candidate']['lib']
    programs={k:(t/(k+'time')).read_bytes() for k in ('base','candidate')}; width=max(map(len,programs.values()))
    programs={k:v+bytes(width-len(v)) for k,v in programs.items()};programs['copy']=programs['base']
    selected=t/'selected';selected.write_bytes(programs['base']);selected.chmod(0o755)
    invoke=['setarch',platform.machine(),'-R',selected]
    samples_checked={}
    for image in samples['images']:
        for sect in image['sections']:
            f=r/'inputs'/sect['file']; assert sha(f)==sect['sha256']
            codes=ref['sections'][f.name]['raw_results_sha256']; samples_checked[f.name]={}
            for k,flags,id in [('base',1,'old1'),('candidate',1,'fixed1'),('candidate',2,'fixed2')]:
                raw=sp.check_output([t/(k+'firmware'),f,str(sect['address']),str(flags)])
                fingerprint=hashlib.sha256(raw).hexdigest();assert fingerprint==codes[id];samples_checked[f.name][id]=fingerprint
            for api in ('iter','array'):
                for mode in range(3):
                    key=f.stem+'/'+api+'/'+str(mode)
                    def take(k,num):
                        if sys.platform.startswith('linux'):
                            selected.write_bytes(programs[k]);args=invoke
                        else:args=[t/(('base' if k=='copy' else k)+'time')]
                        return list(map(int,call(*args,f,str(sect['address']),str(mode),api,str(num)).split()))
                    n=max(1,ceil(30e6/take('base',1)[0]));expected=take('base',n)[2:];rng=random.Random(key+os.environ.get("REPEAT",""));cycles=[]
                    for cycle in range(31):
                        order=keys.copy();rng.shuffle(order);obs={k:[]for k in keys}
                        for k in order+order[::-1]:
                            v=take(k,n);assert v[2:]==expected;obs[k].append(v[:2])
                        cycles.append({k:[sum(x[j]for x in v)for j in (0,1)]for k,v in obs.items()})
                    paired={clk:{k:interval([z[k][j]/z['candidate'][j]for z in cycles])for k in ('base','copy')}for j,clk in enumerate(('cpu','wall'))}
                    result[key]=dict(paired=paired,gain=all(z['ci95'][0]>1 for clock in paired.values()for z in clock.values()),loss=all(z['ci95'][1]<1 for clock in paired.values()for z in clock.values()))
                    rows[key]=dict(repetitions=n,cycles=cycles,counts=expected);put('timings',rows);put('analysis',result)
    put('complete',dict(complete=True,source=q,images=source,samples=samples_checked,panels=len(result),compiler=call('clang','--version'),machine=platform.machine()))
finally:
    size=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t)
    inputs=r/'inputs';input_bytes=sum(f.stat().st_size for f in inputs.glob('*.text'))
    if inputs.is_dir():shutil.rmtree(inputs)
    put('cleanup',dict(bytes=size+input_bytes,removed=not t.exists()and not inputs.exists()))
