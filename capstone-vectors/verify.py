from pathlib import Path
import collections,hashlib,json,os,platform,shutil,subprocess as sp,tempfile
r=Path(__file__).resolve().parent;ci=bool(os.environ.get('GITHUB_ACTIONS'));d=lambda n:next(r.parent.glob(f'round{n}-*'));rd=lambda p:json.loads(p.read_text());out=(r.parent/'evidence' if ci else r);out.mkdir(exist_ok=True)
def save(f,v):(out/(f+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def run(*a):sp.run(a,check=True)
def get(*a):return sp.check_output(a,text=True).strip()
def sha(bytes_):return hashlib.sha256(bytes_).hexdigest()
def file_sha(f):return sha(f.read_bytes())
q=rd(r/'source.json');t=q['capstone'];dev=q['dev'];nd=r.parent/'neverd-config' if ci else r.parent.parent;cap=r.parent/'source' if ci else d(579)/'source';root=Path(tempfile.mkdtemp(dir=r));cases={}
def entries(blob):
 p=8;assert blob[:p]==b'!<arch>\n';mutable=bytearray(blob);stamps={}
 while p<len(blob):
  assert blob[p+58:p+60]==b'\x60\n';n=int(blob[p+48:p+58]);stamps[p]=blob[p+16:p+28].decode().strip();mutable[p+16:p+28]=b' '*12;p+=60+n+(n&1)
 assert p==len(blob) and len(stamps)>48
 return sha(mutable),stamps
try:
 pr=root/'project';s=pr/'third_party/capstone';s.parent.mkdir(parents=True);(pr/'cmake').mkdir();run('git','clone','-q','--shared','--no-checkout',cap,s);run('git','-C',s,'checkout','-q','--detach',t['parent'])
 assert get('git','-C',nd,'rev-parse',dev+':third_party/capstone')==t['parent'];cm=get('git','-C',nd,'show',dev+':CMakeLists.txt');cm=cm[cm.index('# --- Capstone (our fork'):cm.index('# --- NeverD CMake helpers')]
 flag='cmake/NeverDCapstoneCompilerOptions.inc';(pr/flag).write_bytes(sp.check_output(['git','-C',nd,'show',dev+':'+flag]))
 driver=pr/'main.c';driver.write_text('''#include <capstone/capstone.h>
#include <stdio.h>
int main(void){
 csh h; cs_insn *i; const uint8_t mov[]={0x89,0xc1}, local[]={0x20,0x7f};
 if(cs_open(CS_ARCH_X86,CS_MODE_32,&h)||cs_disasm(h,mov,2,0,1,&i)!=1)return 1;
 printf("%u %s %s\\n",i->id,i->mnemonic,i->op_str);cs_free(i,1);cs_close(&h);
 const uint8_t add[]={0x21,0x04,0x00,0x91};
 if(cs_open(CS_ARCH_AARCH64,CS_MODE_LITTLE_ENDIAN,&h)||cs_disasm(h,add,4,0,1,&i)!=1)return 3;
 printf("%u %s %s\\n",i->id,i->mnemonic,i->op_str);cs_free(i,1);cs_close(&h);
 if(cs_support(CS_ARCH_WASM)){
  if(cs_open(CS_ARCH_WASM,CS_MODE_LITTLE_ENDIAN,&h)||cs_disasm(h,local,2,0,1,&i)!=1)return 2;
  printf("%u %s %s\\n",i->id,i->mnemonic,i->op_str);cs_free(i,1);cs_close(&h);
 }
 return 0;
}
''')
 for name,wasm in [('six',False),('seven',True)]:
  (pr/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(MixedLink LANGUAGES C CXX)\n'+('set(CAPSTONE_WASM_SUPPORT ON CACHE BOOL "" FORCE)\n'if wasm else '')+cm+'\nadd_executable(consumer main.c)\ntarget_link_libraries(consumer PRIVATE capstone_static)\ntarget_include_directories(consumer PRIVATE third_party/capstone/include)\n')
  b=root/name;variants={};dates={}
  for label in ('base','candidate'):
   run('git','-C',s,'restore','--source','HEAD','--staged','--worktree','--','.')
   if label=='candidate':
    patch=r/'candidate.patch';assert file_sha(patch)==t['sha256'];run('git','-C',s,'apply','--index',patch);assert get('git','-C',s,'write-tree')==t['tree']
   if label=='base':run('cmake','-G','Ninja','-S',pr,'-B',b,'-DCMAKE_BUILD_TYPE=Release','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON')
   run('cmake','--build',b,'--parallel','4','--target','consumer');lib,=b.rglob('libcapstone.a')
   commands=rd(b/'compile_commands.json');wcmd=[x['command']for x in commands if x['file'].endswith('/WASMInstPrinter.c')]
   acmd=[x['command']for x in commands if x['file'].endswith('/AArch64InstPrinter.c')];assert len(acmd)==1 and 'CAPSTONE_AARCH64_SKIP_UNUSED_OPERAND_DETAIL' not in acmd[0]
   assert bool(wcmd)==wasm and all('CAPSTONE_WASM_LITERAL_MNEMONICS' not in x for x in wcmd)
   objects={str(f.relative_to(b)):file_sha(f)for f in b.rglob('*.c.o') if '/capstone' in str(f.relative_to(b))};assert len(objects)>=60 and any('WASMInstPrinter' in f for f in objects)==wasm
   buf=lib.read_bytes();normalized,dates[label]=entries(buf);exe=b/'consumer';runtime=get(exe)
   variants[label]=dict(archive=sha(buf),normalized_archive=normalized,objects=objects,linked=file_sha(exe),runtime=runtime)
  a,z=variants.values();assert dates['base'].keys()==dates['candidate'].keys()
  changes=[{'header_offset':k,'base':v,'candidate':dates['candidate'][k]}for k,v in dates['base'].items()if dates['candidate'][k]!=v]
  cases[name]=dict(variants=variants,header_date_changes=changes,source_flags=wcmd);save('stages',cases)
  assert {k:v for k,v in a.items()if k!='archive'}=={k:v for k,v in z.items()if k!='archive'},(name,[k for k in a if a[k]!=z[k]],[k for k in a['objects']if a['objects'][k]!=z['objects'][k]])
  assert (a['archive']==z['archive'])==(not changes)
 save('complete',dict(complete=True,source=q,cases=cases,host=platform.platform(),arch=platform.machine(),control_files=sha((cm+(pr/flag).read_text()).encode())))
finally:
 size=sum(f.stat().st_size for f in root.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(root);save('cleanup',dict(bytes=size,removed=not root.exists()))
