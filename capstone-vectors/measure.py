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
 os.environ.pop('CAPSTONE_BENCH_ATT',None)
 run('cmake','--build',b,'--target','capstone_static','--parallel','4')
 lib,=b.rglob('libcapstone.a');exe=w/'profile'
 run('clang++',w/'driver.o',lib,ad/'target/release/libiced_compare.a','-lpthread','-lm','-ldl','-no-pie','-o',exe)
 image=dict(capstone=sha(lib),executable=sha(exe),iced=sha(ad/'target/release/libiced_compare.a'))
 save('image',image)
 def instrument(file,marker,counter,body=False):
     path=src/file
     text=path.read_text()
     assert text.count(marker)==1,(file,marker)
     i=text.index(marker)
     if body:i=text.index('{',i)+1
     text=text[:i]+'\n\textern uint64_t '+counter+'; ++'+counter+';\n\t'+text[i:]
     path.write_text(text)
 instrument('cs.c','MCInst_InitX86(&mci);','profile_full_decodes')
 instrument('arch/X86/X86Disassembler.c','const int ret = decodeInstruction(insn, decode_code, decode_size, mode);','profile_decodes')
 instrument('arch/X86/X86IntelInstPrinter.c','void X86_Intel_printInst(MCInst *MI, SStream *O, void *Info)','profile_prints',True)
 run('cmake','--build',b,'--target','capstone_static','--parallel','4')
 profile=w/'record-profile';run('clang++','-std=c++17','-O2','-I',src,'-I',src/'include',r/'profile.cpp',lib,'-o',profile)
 rows={};selection={}
 for name,spec in samples.items():
  meta,spans=materialize(name,spec,w);assert meta==spec['verified']
  text=w/(name+'.text');ranges=w/(name+'.ranges');bits=str(spec['bits'])
  original=list(spans);skipped=0;removed=[]
  if name=='sqlite-win-x64':
   data=text.read_bytes();initial=[list(map(int,v.split()))for v in get(exe,'audit','0','1',text,ranges,bits).splitlines()]
   excluded_starts={v[2] for v in initial if v[1]!=v[5] or v[3]!=v[4]}
   tables={v['start']:v for v in q['sqlite_tables']};assert set(tables)==excluded_starts
   spans=[]
   for off,length,start in original:
    if start not in tables:spans.append((off,length,start));continue
    v=tables[start];assert off==v['offset'] and length==v['length'] and hashlib.sha256(data[off:off+length]).hexdigest()==v['sha256']
    a,b=v['first']-start,v['end']-start;assert 0<=a<b<=length and b-a==v['words']*4
    if a:spans.append((off,a,start))
    if b<length:spans.append((off+b,length-b,start+b))
    skipped+=b-a;removed.append([off+a,b-a,start+a])
   assert skipped==2272 and len(spans)==9004
   ranges.write_bytes(table_bytes(spans))
  trace=[list(map(int,v.split()))for v in get(exe,'audit','0','1',text,ranges,bits).splitlines()]
  assert [row[:3]for row in trace]==[list(s)for s in spans] and all(v[5]<=v[1] for v in trace)
  included=[row[:3]for row in trace if row[1]==row[5] and row[3]==row[4]];excluded=[row for row in trace if row[1]!=row[5] or row[3]!=row[4]]
  assert included and len(included)+len(excluded)==len(spans)
  assert not excluded and len(included)==q['ranges'][name]['included']
  ranges.write_bytes(table_bytes(included));size=sum(row[1]for row in included)
  assert sha(ranges)==q['ranges'][name]['ranges'] and size==q['ranges'][name]['included_bytes']
  selection[name]=dict(input=meta,same=len(included),bytes=size,sha256=sha(ranges),largest=max(row[1]for row in included),data_bytes=skipped)
  save('selection',selection)
  lines=get(profile,text,ranges,bits).splitlines()
  head=lines.pop(0).split('\t');assert head.pop(0)=='total';head=list(map(int,head))
  expected=q['expected'][platform.machine()][name]
  assert head[:2]==expected['boundary'] and head[2]==size and len(head)==12
  families={}
  for line in lines:
   fields=line.split('\t');assert len(fields) in (15,17)
   key='/'.join(fields[:2]);assert key not in families
   values=list(map(int,fields[2:15]));families[key]=dict(count=values[0],full=values[1:5],decoder=values[5:9],printed=values[9:13],example=fields[15:])
  assert sum(v['count'] for v in families.values())==head[0]
  totals=[head[4+i]+sum(v['full'][i]for v in families.values())for i in range(4)]
  assert totals[2:]==expected['full'],(name,totals,expected)
  rows[name]=dict(header=head,totals=totals,families=families);save('family-counts',rows)
 assert len(rows)==4
 save('complete',dict(complete=True,source=q,host=platform.machine(),selection=selection))
finally:
 size=sum(x.stat().st_size for x in w.rglob('*')if x.is_file() and not x.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=size))
