from pathlib import Path
import hashlib,json,os,shlex,shutil,subprocess as sp,tempfile
r=Path(__file__).resolve().parent;root=r.parent;nd=root/'neverd';src=nd/'third_party/capstone';out=root/'evidence';out.mkdir(exist_ok=True)
m=json.loads((r/'inputs.json').read_text());ref=json.loads((r/'reference-products.json').read_text())
def git(*a):return sp.check_output(['git','-C',src,*map(str,a)],text=True).strip()
def run(args,name):
 with (out/(name+'.log')).open('w')as f:z=sp.run([str(a) for a in args],stdout=f,stderr=sp.STDOUT)
 if z.returncode:print((out/(name+'.log')).read_text()[-1800:]);z.check_returncode()
def save(n,v):(out/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def sha(z):return hashlib.sha256(z).hexdigest()
assert git('rev-parse','HEAD')==m['capstone']
(nd/'cmake').mkdir(exist_ok=True);shutil.copyfile(r/'NeverDCapstoneCompilerOptions.inc',nd/'cmake/NeverDCapstoneCompilerOptions.inc')
t=Path(tempfile.mkdtemp(dir=os.environ['RUNNER_TEMP']));b=t/'build'
try:
 for label in ['base', 'default', 'mips_trim', 'indirect_targets', 'combined']:
  entry=m['variants'].get(label,{});expected=ref['objects']['base' if label=='default' else label]
  policy=(r/(label+'-root.cmake')).read_text()
  h=sp.check_output(['git','hash-object','--stdin'],input=policy.encode()).decode().strip()
  assert h==entry.get('build_blob',m['build_blob'])
  a=policy.index('# --- Capstone (our fork');z=policy.index('endforeach()',a)+len('endforeach()')
  (nd/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.20)\nproject(DecoderConsumer LANGUAGES C CXX)\n'+policy[a:z]+'\n')
  if label!='base':
   patch=r/entry['capstone_patch'];assert sha(patch.read_bytes())==entry['capstone_sha256']
   git('apply','--index',patch);assert git('write-tree')==entry['tree']
  run(['cmake','-S',nd,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON','-DCMAKE_C_COMPILER=clang','-DCMAKE_CXX_COMPILER=clang++','-DCMAKE_C_FLAGS=-Wno-error=incompatible-pointer-types-discards-qualifiers'],'configure-'+label)
  run(['cmake','--build',b,'--parallel','4','--target','capstone_static'],'build-'+label)
  cmds=json.loads((b/'compile_commands.json').read_text())
  hits=[Path(c['file']).name for c in cmds if '-DCAPSTONE_MIPS_PRECHECK_PRINTED_ALIAS' in shlex.split(c['command'])]
  assert hits==['MipsMapping.c']
  defs={k:[Path(c['file']).name for c in cmds if '-D'+k in shlex.split(c['command'])] for k in ('CAPSTONE_MIPS_FINAL_OUTPUT_TRIM','CAPSTONE_X86_NEAR_INDIRECT_OUTPUT')}
  assert defs['CAPSTONE_MIPS_FINAL_OUTPUT_TRIM']==(['MipsInstPrinter.c'] if label in ('mips_trim','combined') else [])
  assert defs['CAPSTONE_X86_NEAR_INDIRECT_OUTPUT']==(['X86Sse64Output.c'] if label in ('indirect_targets','combined') else [])
  save(label+'-options',defs)
  lib,=b.rglob('libcapstone.a');members=sp.check_output(['ar','t',lib],text=True).splitlines()
  assert len(members)==len(set(members))==42
  hashes={n:sha(sp.check_output(['ar','p',lib,n])) for n in members}
  prior={Path(k).name:v for k,v in expected.items()};assert prior.keys()==hashes.keys()
  different={k:dict(current=v,product=prior[k])for k,v in hashes.items()if v!=prior[k]}
  save(label,dict(source=git('write-tree'),root=h,objects=hashes,different=different,flag=hits))
  assert not different,(label,list(different))
  if label!='base':git('reset','--hard',m['capstone'])
 save('complete',dict(complete=True,source=m['neverd'],release=m['variants']['combined']['commit'],baseline=m['capstone'],members=42,compared=5,reference_run=ref['run']['id'],llvm_compiler=sp.check_output(['clang','--version'],text=True).splitlines()[0]))
finally:
 size=sum(f.stat().st_size for f in t.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(t)
 save('cleanup',dict(removed=not t.exists(),bytes=size))
