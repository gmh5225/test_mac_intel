from pathlib import Path
import json,math,os,platform,shlex,shutil,statistics,subprocess as sp
import corpus,run

def main():
 s,w,e=run.SOURCE,run.WORK,run.EVIDENCE
 w.mkdir();e.mkdir();m=json.loads((s/'manifest.json').read_text())
 cs=run.fetch('new','https://github.com/NeverSight/capstone.git',m['capstone_revision'])
 run.command(['git','apply',s/'candidate.patch'],'apply-tested-shared-lookups',cs)
 iced=run.fetch('iced','https://github.com/NeverSight/iced.git',m['iced_revision'])
 fixtures=corpus.prepare(s,w,e,run.command);d=run.build('new')
 adapter=w/'adapter';adapter.mkdir()
 for f in ('iced.rs','Cargo.lock'):shutil.copyfile(s/f,adapter/f)
 (adapter/'Cargo.toml').write_text("""[package]
name="iced_compare"
version="0.1.0"
edition="2021"
[lib]
crate-type=["staticlib"]
path="iced.rs"
[dependencies]
iced-x86={path="../iced/src/rust/iced-x86",default-features=false,features=["std","decoder","intel","instr_info"]}
[profile.release]
opt-level=3
panic="abort"
""")
 run.command(['cargo','build','--locked','--release','--manifest-path',adapter/'Cargo.toml'],'iced')
 defs=[arg for arg in shlex.split(next(a['command'] for a in json.loads((d/'compile_commands.json').read_text()) if a['file'].endswith('/Mapping.c'))) if arg.startswith('-D')]
 run.command(['clang','-O3',*defs,'-I',cs,'-I',cs/'include','-c',s/'bind.c','-o',w/'bind.o'],'bind')
 v=(s/'compare.cpp').read_text()
 v=v.replace('static Result capstone_run(','''extern "C" cs_err storage_open(cs_mode, csh *);
extern "C" void storage_bind(csh, cs_mode, cs_insn *, uintptr_t *);
extern "C" void storage_restore(csh);
static uintptr_t addrs[5];
static double cpu_roi;
static long long wall_roi;
static Result capstone_run(''')
 v=v.replace('cs_open(CS_ARCH_X86, m, &handle)','storage_open(m, &handle)')
 v=v.replace('#endif\n  for (unsigned repeat', '''#endif
  storage_bind(handle,m,insn,addrs);
  auto c0=process_cpu_ns(); auto w0=std::chrono::steady_clock::now();
  for (unsigned repeat''')
 v=v.replace('  cs_free(insn, 1);\n  cs_close(&handle);\n  return result;', '''  wall_roi=std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now()-w0).count();
  cpu_roi=process_cpu_ns()-c0;
  storage_restore(handle);
  cs_free(insn, 1);
  cs_close(&handle);
  return result;''')
 a=v.index('    std::printf("{');b=v.index('    return 0;',a)
 v=v[:a]+r'''    std::printf("{\"cpu_ns\":%.0f,\"wall_ns\":%lld,\"instructions\":%llu,\"rejected\":%llu,\"boundary\":\"%016llx\",\"value\":\"%016llx\",\"low16\":[%lu,%lu,%lu,%lu,%lu]}\n",cpu_roi,wall_roi,(unsigned long long)result.instructions,(unsigned long long)result.rejected,(unsigned long long)result.boundaries,(unsigned long long)result.values,(unsigned long)addrs[0],(unsigned long)addrs[1],(unsigned long)addrs[2],(unsigned long)addrs[3],(unsigned long)addrs[4]);
'''+v[b:]
 assert v.count('storage_bind(handle,m,insn,addrs)')==1 and v.count('storage_restore(handle)')==1
 (w/'compare.cpp').write_text(v)
 run.command(['clang++','-O3','-DNDEBUG','-std=c++17','-I',cs/'include',w/'compare.cpp',w/'bind.o',d/'libcapstone.a',adapter/'target/release/libiced_compare.a','-lpthread','-ldl','-lm','-o',w/'storage'],'link')
 if platform.system()=='Linux':
  avail=sorted(os.sched_getaffinity(0));os.sched_setaffinity(0,{avail[0]});assert sorted(os.sched_getaffinity(0))==[avail[0]]
 run.write('build.json',dict(binary=run.sha(w/'storage'),library=run.sha(d/'libcapstone.a'),candidate=run.sha(s/'candidate.patch'),host=list(platform.uname()),capstone=m['capstone_revision'],iced=m['iced_revision']))
 def invoke(f,mode,k,n):
  raw=sp.check_output([w/'storage','capstone',mode,str(f['selector']),str(n),f['path']],env=dict(os.environ,LOOKUP_POLICY=str(k)))
  return json.loads(raw)
 chosen=[(f,mode) for f in fixtures if f['name'] in ('putty-32-0.85','putty-64-0.85','simd64','scalar32','scalar64') for mode in ('scan','format','detail') if mode!='scan' or f['name']=='putty-32-0.85']
 assert len(chosen)==11,[(f['name'],mode) for f,mode in chosen]
 ns=[]
 for f,mode in chosen:
  one=invoke(f,mode,0,1);q=max(1,round(40e6/max(one['cpu_ns'],1)));x=invoke(f,mode,0,q);ns.append(max(1,round(140e6*q/max(x['cpu_ns'],1))))
 # Each policy takes each ordinal equally. Second quartet gives A/A within a cycle.
 square=[0,1,3,2];rows=[]
 with (e/'raw.jsonl').open('w') as out:
  for cycle in range(12):
   for i in range(len(chosen)):
    j=(i+7*cycle)%len(chosen);f,mode=chosen[j];signature=None
    for k in range(8):
     policy=(square[k%4]+cycle+(2 if k>=4 else 0))%4
     result=invoke(f,mode,policy,ns[j]);sig=tuple(result[a]for a in ('instructions','rejected','boundary','value'))
     if signature is None:signature=sig
     assert signature==sig and result['cpu_ns']>0
     row=dict(case=f['name'],mode=mode,cycle=cycle,ordinal=k,policy=policy,repeats=ns[j],**result);rows.append(row);out.write(json.dumps(row)+'\n')
   out.flush()
 summary=[]
 for f,mode in chosen:
  by=lambda k,c:[x['cpu_ns'] for x in rows if x['case']==f['name'] and x['mode']==mode and x['policy']==k and x['cycle']==c]
  for a,b,label in [(0,1,'heap-open: heap vs static maps'),(2,3,'shared-open: heap vs static maps'),(0,2,'heap maps: heap vs shared open'),(1,3,'static maps: heap vs shared open'),(0,3,'natural heap vs natural shared')]:
   ratios=[math.prod(by(a,c))**0.5/(math.prod(by(b,c))**0.5) for c in range(12)]
   summary.append(dict(case=f['name'],mode=mode,a=a,b=b,label=label,gain=statistics.median(ratios),wins=sum(v>1 for v in ratios)))
 run.write('summary.json',summary)
if __name__=='__main__':
 try:main()
 finally:
  if run.EVIDENCE.exists():run.cleanup()
