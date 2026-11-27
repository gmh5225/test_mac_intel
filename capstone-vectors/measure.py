"""Measure new PE and ELF inputs after checking every candidate instruction boundary."""
from pathlib import Path
import hashlib,json,math,os,platform,random,shutil,subprocess as sp,tempfile
from fixtures import materialize,table_bytes
from fixed_image import FixedImage
r=Path(__file__).resolve().parent;p=r.parent;src=p/'source';nd=p/'neverd-config';ice=p/'iced-source';e=p/'evidence';e.mkdir(exist_ok=True)
rd=lambda f:json.loads(f.read_bytes())
def save(k,v):
 f=e/(k+'.json');tmp=f.with_suffix('.tmp');tmp.write_text(json.dumps(v,indent=1)+'\n');tmp.replace(f)
def get(*cmd,**kw):return sp.check_output(cmd,text=True,**kw).strip()
def run(*cmd,**kw):sp.run(cmd,check=True,**kw)
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
q=rd(r/'source.json');samples=rd(r/'samples.json');w=Path(tempfile.mkdtemp());stages=('shipping','base','candidate','group1')
try:
 for path,revision in [(src,q['shipping']['commit']),(nd,q['dev']),(ice,q['iced'])]:assert get('git','-C',path,'rev-parse','HEAD')==revision
 for name,dig in q['drivers'].items():assert sha(r/name)==dig
 pr=w/'cmake-root';(pr/'third_party').mkdir(parents=True);(pr/'third_party/capstone').symlink_to(src)
 (pr/'cmake').mkdir();conf='cmake/NeverDCapstoneCompilerOptions.inc';shutil.copyfile(nd/conf,pr/conf)
 doc=(nd/'CMakeLists.txt').read_text();(pr/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(NewInputs LANGUAGES C CXX)\n'+doc[doc.index('# --- Capstone (our fork'):doc.index('# --- NeverD CMake helpers')])
 b=w/'build';run('cmake','-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-S',pr,'-B',b)
 ad=w/'rust';ad.mkdir();(ad/'Cargo.toml').write_text((r/'Cargo.toml').read_text().replace('ICED_ROOT',str(ice)))
 for f in ('Cargo.lock','iced.rs'):shutil.copyfile(r/f,ad/f)
 run('cargo','build','--locked','--release',cwd=ad)
 run('clang++','-O3','-DNDEBUG','-std=c++17','-I',src,'-I',src/'include','-c',r/'driver.cpp','-o',w/'driver.o')
 products={}
 for tag in stages:
  run('git','-C',src,'restore','--source','HEAD','--worktree','--staged','--','.')
  if tag!='shipping':
   patch=r/(tag+'.patch');assert sha(patch)==q[tag]['patch'];run('git','-C',src,'apply','--index',patch)
  assert get('git','-C',src,'write-tree')==q[tag]['tree']
  run('cmake','--build',b,'--target','capstone_static','--parallel','4')
  lib,=b.rglob('libcapstone.a');exe=w/tag
  run('clang++',w/'driver.o',lib,ad/'target/release/libiced_compare.a','-lpthread','-lm','-ldl','-no-pie','-o',exe)
  products[tag]=dict(library=sha(lib),exe=sha(exe))
 arm=platform.machine()=='aarch64';assert (products['base']==products['candidate'])==arm
 save('products',products)
 os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
 image=FixedImage(w/'selected',{tag:(w/tag).read_bytes() for tag in stages},True)
 selections={};observed={};audit={}
 for name,spec in samples.items():
  metadata,spans=materialize(name,spec,w);assert metadata==spec['verified']
  text=w/(name+'.text');ranges=w/(name+'.ranges');bits=str(spec['bits']);image.select('shipping')
  trace=[list(map(int,v.split()))for v in get(w/'selected','audit','0','1',text,ranges,bits).splitlines()]
  assert [row[:3]for row in trace]==[list(s)for s in spans] and all(v[5]<=v[1] for v in trace)
  included=[row[:3]for row in trace if row[1]==row[5] and row[3]==row[4]];excluded=[row for row in trace if row[1]!=row[5] or row[3]!=row[4]]
  assert included and len(included)+len(excluded)==len(spans)
  for stage in ('base','candidate','group1'):
   image.select(stage)
   assert [list(map(int,v.split()))for v in get(w/'selected','audit','0','1',text,ranges,bits).splitlines()]==trace
  ranges.write_bytes(table_bytes(included));selections[name]=dict(source=metadata,included=len(included),included_bytes=sum(n for _,n,_ in included),excluded=excluded,ranges=sha(ranges));audit[name]=trace;save('selections',selections);save('boundary-audit',audit)
  for route in ('private','capstone'):
   for dialect,mode in [('intel',0),('intel',1),('intel',2),('att',1),('att',2)]:
    engine=['iced']+(['fast'] if dialect=='intel' and mode else [])
    labels=[*stages,'copy','repeat',*engine]
    def take(label,reps):
     competitor=label in engine;image.select('shipping' if competitor else label);env=dict(os.environ)
     if dialect=='att':env['CAPSTONE_BENCH_ATT']='1'
     else:env.pop('CAPSTONE_BENCH_ATT',None)
     vals=list(map(int,get('setarch',platform.machine(),'-R',w/'selected',label if competitor else route,str(mode),str(reps),text,ranges,bits,env=env).split()))
     assert len(vals)==6 and min(vals[:2])>0;return vals
    reps=max(1,math.ceil(25e6/take('base',1)[0]));checks={k:take(k,reps)[2:]for k in labels}
    assert all(z[:3]==checks['shipping'][:3] for z in checks.values())
    assert all(checks[k]==checks['shipping'] for k in labels if k not in engine)
    key='/'.join((name,route,dialect,str(mode)));rng=random.Random(key);blocks=[]
    for _ in range(17):
     rng.shuffle(labels);values={k:[] for k in labels}
     for label in labels+labels[::-1]:
      sample=take(label,reps);assert sample[2:]==checks[label];values[label].append(sample[:2])
     blocks.append({k:[sum(x[i] for x in v)for i in (0,1)] for k,v in values.items()})
    observed[key]=dict(reps=reps,checks=checks,blocks=blocks);save('timings',observed)
 assert len(selections)==4 and len(observed)==40
 save('complete',dict(complete=True,source=q,samples=samples,images=image.receipt(),host=platform.machine(),cpu=get('lscpu'),compiler=get('clang','--version').splitlines()[0],panels=len(observed)))
finally:
 size=sum(x.stat().st_size for x in w.rglob('*')if x.is_file() and not x.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=size))
