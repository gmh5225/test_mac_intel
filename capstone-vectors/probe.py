from pathlib import Path
import ctypes,json,os,resource,signal,subprocess as sp,tempfile
e=Path('evidence').resolve();e.mkdir(exist_ok=True)
def save(k,z):(e/(k+'.json')).write_text(json.dumps(z,indent=2)+'\n')
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
fixture=0xfedcba9876543210
c='''#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <cpuid.h>
typedef uint64_t (*operation)(uint64_t);
extern const operation tests[];
int main(int argc,char **argv) {
 unsigned a,b,c,d; if(!__get_cpuid(0x80000001,&a,&b,&c,&d))return 1;
 if(argc==1){printf("%u\\n",(c>>6)&1);return 0;}
 if(!(c&(1u<<6)))return 2;
 printf("%016llx\\n",(unsigned long long)tests[atoi(argv[1])](UINT64_C(0xfedcba9876543210)));return 0;
}
'''
rows=[];funcs=[];functions=[]
for rex in ('','44'):
 for reg in range(8):
  for rm in range(8):
   name='check_'+str(len(rows));mr=0xc0|reg<<3|rm
   raw=bytes.fromhex('66'+rex+'0f78'+f'{mr:02x}'+'0804')
   rows.append(dict(rex=rex,reg=reg,rm=rm,raw=raw.hex()));functions.append(name)
   funcs.extend(['.text','.type '+name+',@function',name+':',f'movq %rdi,%xmm{rm}', '.byte '+','.join(hex(x)for x in raw),f'movq %xmm{rm},%rax','ret','.size '+name+',.-'+name])
funcs+=['.section .data.rel.ro.local,"aw"','.p2align 3','.globl tests','tests:']+['.quad '+s for s in functions]+['.section .note.GNU-stack,"",@progbits']
with tempfile.TemporaryDirectory()as tmp:
 t=Path(tmp);(t/'check.c').write_text(c);(t/'select.S').write_text('\n'.join(funcs)+'\n')
 sp.run(['cc','-O2',t/'check.c',t/'select.S','-o',t/'check'],check=True)
 supported=int(sp.check_output([t/'check']));info=Path('/proc/cpuinfo').read_text().partition('\n\n')[0].splitlines()
 model=next(s.split(':',1)[1].strip()for s in info if s.startswith('model name'));vendor=next(s.split(':',1)[1].strip()for s in info if s.startswith('vendor_id'))
 if supported:
  for j,row in enumerate(rows):
   v=sp.run([t/'check',str(j)],capture_output=True,text=True)
   assert v.returncode in (0,-signal.SIGILL) and not v.stderr,(row,v)
   row.update(status='completed'if v.returncode==0 else 'SIGILL',result=v.stdout.strip()if v.returncode==0 else None)
   if row['reg']==0 and not row['rex']:assert v.returncode==0 and int(row['result'],16)==(fixture>>4)&0xff,row
 save('selector',dict(model=model,vendor=vendor,sse4a=bool(supported),fixture=hex(fixture),results=rows if supported else []))
 size=sum(i.stat().st_size for i in t.iterdir())
save('cleanup',dict(removed=not t.exists(),bytes=size))
