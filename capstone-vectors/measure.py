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
 from self_cost import read as read_cost
 patch=r/'profiled.patch';assert sha(patch)==q['profiled']['patch']
 run('git','-C',src,'apply','--index',patch);assert get('git','-C',src,'write-tree')==q['profiled']['tree']
 os.environ['CAPSTONE_BENCH_ATT']='1'
 run('cmake','--build',b,'--target','capstone_static','--parallel','4')
 lib,=b.rglob('libcapstone.a');exe=w/'profile'
 run('clang++',w/'driver.o',lib,ad/'target/release/libiced_compare.a','-lpthread','-lm','-ldl','-no-pie','-o',exe)
 image=dict(capstone=sha(lib),executable=sha(exe),iced=sha(ad/'target/release/libiced_compare.a'))
 save('image',image)
 def measured_set(rows):
  # Order by a digest of the interval, independent of opcode, output, or timings.
  # Pick complete audited extents, including at least one if all exceed the target.
  order=sorted(rows,key=lambda row:hashlib.sha256(table_bytes([row])).digest())
  target=49152;selected=[];size=0
  for row in order:
   if size+row[1]<=target:selected.append(row);size+=row[1]
  return sorted(selected or [min(order,key=lambda row:row[1])])
 rows={};selection={}
 for name,spec in samples.items():
  meta,spans=materialize(name,spec,w);assert meta==spec['verified']
  text=w/(name+'.text');ranges=w/(name+'.ranges');bits=str(spec['bits'])
  audit=[list(map(int,line.split()))for line in get(exe,'audit','0','1',text,ranges,bits).splitlines()]
  assert [x[:3]for x in audit]==[list(t)for t in spans]
  common=[x[:3]for x in audit if x[1]==x[5] and x[3]==x[4]]
  selected=measured_set(common);ranges.write_bytes(table_bytes(selected))
  selection[name]=dict(input=meta,same=len(common),excluded=len(audit)-len(common),intervals=selected,bytes=sum(t[1]for t in selected),sha256=sha(ranges))
  save('selection',selection)
  rows[name]={};boundary=None
  for engine in ('capstone','private','iced'):
   for mode in ((1,2,3) if engine=='fast' else (0,1,2,3)):
    key=engine+'/'+str(mode);lab=name+'-'+engine+'-'+str(mode)
    command=[exe,engine,str(mode),'1',text,ranges,bits]
    expected=list(map(int,get(*command).split()))[2:]
    if boundary is None:boundary=expected[:3]
    assert expected[:3]==boundary and expected[0]>0
    raw=w/(lab+'.cg');log=w/(lab+'.log')
    values=list(map(int,get('valgrind','--tool=callgrind','--instr-atstart=no','--branch-sim=yes','--callgrind-out-file='+str(raw),'--log-file='+str(log),*command).split()))[2:]
    assert values==expected
    dump,=[f for f in w.glob(raw.name+'.*') if 'Client Request: measured decoder spans' in f.read_text(errors='replace')]
    cost=read_cost(dump,e,lab);ev=cost['events']
    assert ev['Ir']==cost['accounted']['Ir'] and ev['Ir']>expected[0]*5 and ev['Bc']>0
    rows[name][key]=dict(codes=expected,ops=cost,rates={k:v/sum(expected[:2]) for k,v in ev.items()})
    save('costs',rows)
    import gzip
    packed=e/(lab+'.cg.gz')
    with dump.open('rb')as a,gzip.open(packed,'wb',compresslevel=6)as dest:shutil.copyfileobj(a,dest)
    with gzip.open(packed,'rb')as a:assert hashlib.sha256(a.read()).hexdigest()==sha(dump)
    for f in [raw,dump,log]:f.unlink(missing_ok=True)
 assert len(rows)==4 and all(len(v)==12 for v in rows.values())
 save('complete',dict(complete=True,source=q,host=platform.machine(),image=image,valgrind=get('valgrind','--version'),selection=selection))
finally:
 size=sum(x.stat().st_size for x in w.rglob('*')if x.is_file() and not x.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=size))
