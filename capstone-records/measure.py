from pathlib import Path
import json,os,platform,shutil,statistics,subprocess as sp,sys,tempfile
import corpus
src=Path(__file__).resolve().parent;w=Path(sys.argv[1]).resolve();out=Path(sys.argv[2]).resolve();out.mkdir(exist_ok=True)
def write(name,data):(out/(name+'.json')).write_text(json.dumps(data,indent=2)+'\n')
def run(args,label):
 with (out/(label+'.log')).open('w') as f:rc=sp.run(list(map(str,args)),stdout=f,stderr=sp.STDOUT).returncode
 if rc:raise RuntimeError((label,(out/(label+'.log')).read_text()[-1300:]))
assert sp.check_output(['git','-C',w,'rev-parse','HEAD'],text=True).strip()==json.loads((src/'manifest.json').read_text())['capstone_revision']
env=dict(platform=platform.platform(),compiler=sp.check_output(['clang','--version'],text=True).splitlines()[0])
if hasattr(os,'sched_getaffinity'):
 env['affinity']=min(os.sched_getaffinity(0));os.sched_setaffinity(0,{env['affinity']})
write('environment',env)
with tempfile.TemporaryDirectory(prefix='capstone-record-cost-') as temp:
 t=Path(temp);b=t/'build'
 try:
  cases=corpus.prepare(src,t,out,run)
  run(['cmake','-S',w,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang','-DCMAKE_C_FLAGS_RELEASE=-O3 -DNDEBUG -fomit-frame-pointer -Wno-error=incompatible-pointer-types-discards-qualifiers','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',*['-DCAPSTONE_'+a+'_SUPPORT=ON' for a in ('X86','ARM','AARCH64','MIPS')],'-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF'],'configure')
  run(['cmake','--build',b,'--target','capstone_static','--parallel','4'],'build')
  run(['clang++','-O3','-DNDEBUG','-std=c++17','-I',w/'include',src/'probe.cpp',b/'libcapstone.a','-o',t/'probe'],'probe')
  def call(case,full,method,reps):
   row=list(map(int,sp.check_output(list(map(str,[t/'probe',case['path'],case['selector'],full,method,reps])),text=True).split()))
   assert len(row)==6 and row[0]>0 and row[1]>0
   return row
  results=[];checks=[]
  for case in cases:
   for full in (0,1):
    audit=call(case,full,2,3);ref=call(case,full,0,3);assert audit[1:5]==ref[1:5] and audit[5]>0
    checks.append(dict(case=case['name'],detail=full,accepted=audit[1],rejected=audit[2],hits=audit[5],complete_public_comparisons=audit[1]+audit[2]));write('audit',checks)
    if len(sys.argv)>3 and sys.argv[3]=='audit':continue
    # Timed calls use the same executable; each traversal creates an empty cache.
    one=call(case,full,0,1);reps=max(1,min(5000,round(50000/one[0])))
    pairs=[];oracle=None
    for index in range(9):
     order=(0,1,2,2,1,0) if index%2==0 else (2,0,1,1,0,2)
     rows={0:[],1:[],2:[]}
     for who in order:
      ticks=call(case,full,1 if who==1 else 0,reps);rows[who].append(ticks[0])
      if oracle is None:oracle=ticks[1:5]
      assert ticks[1:5]==oracle
     pairs.append(dict(times=rows,gain=sum(rows[0])/sum(rows[1]),aa=sum(rows[0])/sum(rows[2])))
    results.append(dict(case=case['name'],detail=full,reps=reps,hit_share=audit[5]/(audit[1]+audit[2]),gain=statistics.median(x['gain'] for x in pairs),aa=statistics.median(x['aa']for x in pairs),pairs=pairs))
    write('timings',results)
  write('complete',dict(cells=len(checks),timed=len(results),comparisons=sum(x['complete_public_comparisons'] for x in checks),hits=sum(x['hits'] for x in checks)))
 finally:
  size=sum(f.stat().st_size for f in t.rglob('*') if f.is_file());shutil.rmtree(t);write('cleanup',dict(bytes=size,removed=not t.exists()))
