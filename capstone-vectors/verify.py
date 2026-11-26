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
 assert get('git','-C',nd,'rev-parse',dev+':third_party/capstone')==q['oldbase']['commit'];cm=get('git','-C',nd,'show',dev+':CMakeLists.txt');cm=cm[cm.index('# --- Capstone (our fork'):cm.index('# --- NeverD CMake helpers')]
 flag='cmake/NeverDCapstoneCompilerOptions.inc';(pr/flag).write_bytes(sp.check_output(['git','-C',nd,'show',dev+':'+flag]))
 driver=pr/'main.c';driver.write_text('''#include <capstone/capstone.h>
#include <stdio.h>
#include "third_party/capstone/arch/X86/X86ScanAdapter.h"
int main(void){
 csh h; cs_insn *i; const uint8_t mov[]={0x89,0xc1}, local[]={0x20,0x7f};
 if(cs_open(CS_ARCH_X86,CS_MODE_32,&h)||cs_disasm(h,mov,2,0,1,&i)!=1)return 1;
 printf("%u %s %s\\n",i->id,i->mnemonic,i->op_str);cs_free(i,1);cs_close(&h);
 const uint8_t mask[]={0xc5,0xf8,0x93,0xc1};
 if(cs_open(CS_ARCH_X86,CS_MODE_64,&h)||cs_option(h,CS_OPT_TEXT,CS_OPT_OFF))return 4;
 uint32_t id=0;X86ScanBatchResult m=X86_scanNativeBatch(h,mask,4,0,&id,1);
 if(m.count!=1||m.bytes!=4||(id>>8)!=X86_INS_KMOVW)return 5;
 printf("%u\\n",id);cs_close(&h);
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
  for label in ('oldbase','capstone','oldboth','newboth','oldbatch','newbatch'):
   run('git','-C',s,'restore','--source','HEAD','--staged','--worktree','--','.')
   if label!='oldbase':
    f=r/(label+'.patch');assert file_sha(f)==q['patches'][label];run('git','-C',s,'apply','--index',f)
   assert get('git','-C',s,'write-tree')==q[label]['tree']
   if label=='oldbase':run('cmake','-G','Ninja','-S',pr,'-B',b,'-DCMAKE_BUILD_TYPE=Release','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON')
   run('cmake','--build',b,'--parallel','4','--target','consumer');lib,=b.rglob('libcapstone.a')
   commands=rd(b/'compile_commands.json');wcmd=[x['command']for x in commands if x['file'].endswith('/WASMInstPrinter.c')]
   acmd=[x['command']for x in commands if x['file'].endswith('/AArch64InstPrinter.c')];assert len(acmd)==1 and 'CAPSTONE_AARCH64_SKIP_UNUSED_OPERAND_DETAIL' not in acmd[0]
   armcmd=[x['command']for x in commands if x['file'].endswith('/ARMInstPrinter.c')];assert len(armcmd)==1 and 'CAPSTONE_ARM_ONLY' not in armcmd[0]
   assert bool(wcmd)==wasm and all('CAPSTONE_WASM_LITERAL_MNEMONICS' not in x for x in wcmd)
   objects={str(f.relative_to(b)):file_sha(f)for f in b.rglob('*.c.o') if '/capstone' in str(f.relative_to(b))};assert len(objects)>=60 and any('WASMInstPrinter' in f for f in objects)==wasm
   buf=lib.read_bytes();normalized,dates[label]=entries(buf);exe=b/'consumer';runtime=get(exe)
   variants[label]=dict(archive=sha(buf),normalized_archive=normalized,objects=objects,linked=file_sha(exe),runtime=runtime)
  pairs={}
  for x,y in [('oldbase','capstone'),('oldboth','newboth'),('oldbatch','newbatch')]:
   a,z=variants[x],variants[y];assert dates[x].keys()==dates[y].keys()
   changed=sum(v!=dates[y][k]for k,v in dates[x].items())
   assert all(a[k]==z[k]for k in ('normalized_archive','objects','linked','runtime')),(name,x,y)
   assert (a['archive']==z['archive'])==(changed==0)
   pairs[x+'/'+y]={'different_archive_timestamps':changed,'normalized_archive':a['normalized_archive'],'linked':a['linked']}
  assert len({variants[k]['normalized_archive']for k in ('oldbase','oldboth','oldbatch')})==3
  cases[name]=dict(variants=variants,proofs=pairs);save('stages',cases)
 save('complete',dict(complete=True,source=q,cases=cases,host=platform.platform(),arch=platform.machine(),control_files=sha((cm+(pr/flag).read_text()).encode())))
finally:
 size=sum(f.stat().st_size for f in root.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(root);save('cleanup',dict(bytes=size,removed=not root.exists()))
