from pathlib import Path
import gzip,json,os,shutil,subprocess as sp
import corpus,run
def main():
 s=run.SOURCE;w=run.WORK;e=run.EVIDENCE;w.mkdir();e.mkdir();m=json.loads((s/'manifest.json').read_text())
 cs=run.fetch('base','https://github.com/NeverSight/capstone.git',m['capstone_revision'])
 iced=run.fetch('iced','https://github.com/NeverSight/iced.git',m['iced_revision'])
 fixtures=corpus.prepare(s,w,e,run.command);b=run.build('base')
 adapter=w/'adapter';adapter.mkdir();shutil.copyfile(s/'Cargo.lock',adapter/'Cargo.lock')
 (adapter/'Cargo.toml').write_text("""[package]
name = "iced_compare"
version = "0.1.0"
edition = "2021"
[lib]
crate-type = ["staticlib"]
path = "iced.rs"
[dependencies]
iced-x86 = { path="../iced/src/rust/iced-x86", default-features=false, features=["std","decoder","intel","instr_info"] }
[profile.release]
opt-level=3
debug=1
panic="abort"
""")
 rs=(s/'iced.rs').read_text()
 assert rs.count('while decoder.can_decode() {')==1 and rs.count('*output = result;')==1
 rs='extern "C" { fn start_profile(); fn stop_profile(); }\n'+rs
 rs=rs.replace('while decoder.can_decode() {','start_profile();\n        while decoder.can_decode() {').replace('    *output = result;','    stop_profile();\n    *output = result;')
 (adapter/'iced.rs').write_text(rs);run.command(['cargo','build','--release','--locked','--manifest-path',adapter/'Cargo.toml'],'build-iced')
 cpp=(s/'compare.cpp').read_text()
 prefix='''#include <valgrind/callgrind.h>
static bool measuring;
extern "C" void start_profile(){ if(measuring) { CALLGRIND_START_INSTRUMENTATION; CALLGRIND_ZERO_STATS; } }
extern "C" void stop_profile(){ if(measuring) { CALLGRIND_STOP_INSTRUMENTATION; } }
'''
 cpp=prefix+cpp
 pos=cpp.index('  for (unsigned repeat = 0; repeat < repeats; ++repeat) {',cpp.index('#endif',cpp.index('#ifdef USE_BATCH',cpp.index('static Result capstone_run'))))
 cpp=cpp[:pos]+'  start_profile();\n'+cpp[pos:]
 pos=cpp.index('  cs_free(insn, 1);',pos);cpp=cpp[:pos]+'  stop_profile();\n'+cpp[pos:]
 assert cpp.count('Result result = run(repeats);')==1
 cpp=cpp.replace('Result result = run(repeats);','measuring = true;\n    Result result = run(repeats);\n    measuring = false;')
 (w/'profile.cpp').write_text(cpp)
 run.command(['clang++','-O3','-gline-tables-only','-DNDEBUG','-std=c++17','-I',cs/'include',w/'profile.cpp',b/'libcapstone.a',adapter/'target/release/libiced_compare.a','-pthread','-ldl','-lm','-o',w/'profile'],'build-consumer')
 rows=[]
 for case in fixtures:
  if case['name'] not in ('putty-32-0.85','simd64'):continue
  for mode in ('scan','format','detail'):
   boundary=None
   for engine in ('capstone',):
    tag='-'.join([case['name'],mode,engine]);dest=w/(tag+'.out')
    run.command(['valgrind','--tool=callgrind','--instr-atstart=no','--dump-instr=yes','--cache-sim=yes','--branch-sim=yes','--callgrind-out-file='+str(dest),w/'profile',engine,mode,case['selector'],1,case['path']],tag)
    res=next(json.loads(x) for x in (e/(tag+'.log')).read_text().splitlines() if x.startswith('{'));pairs=tuple(res[k] for k in ('instructions','rejected','boundary_hash'))
    if boundary is None:boundary=pairs
    assert pairs==boundary,(case['name'],mode,engine,res,boundary)
    raw=dest.read_bytes();events=next(x.split()[1:]for x in raw.splitlines() if x.startswith(b'events:'));totals=next(x.split()[1:]for x in raw.splitlines() if x.startswith(b'totals:'));counts={k.decode():int(v) for k,v in zip(events,totals)}
    assert counts['Ir']>res['instructions']*45
    (e/(tag+'.callgrind.gz')).write_bytes(gzip.compress(raw));dest.unlink()
    rows.append(dict(case=case['name'],engine=engine,mode=mode,public=res,counters=counts));run.write('counters.json',rows)
 assert len(rows)==6;run.write('complete.json',dict(rows=len(rows),capstone=m['capstone_revision'],iced=m['iced_revision']))
if __name__=='__main__':
 try:main()
 finally:
  if run.EVIDENCE.exists():run.cleanup()
