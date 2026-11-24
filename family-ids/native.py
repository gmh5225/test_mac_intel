from pathlib import Path
import hashlib,json,os,platform,shlex,shutil,struct,subprocess as sp,tempfile
r=Path(__file__).resolve().parent;p=r.parent;src=p/'source';nd=p/'neverd';e=p/'evidence';e.mkdir(exist_ok=True)
rd=lambda f:json.loads(f.read_text());q=rd(r/'source.json')
def save(k,v):(e/(k+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def get(*a,**kw):return sp.check_output(a,text=True,**kw)
def run(*a,**kw):sp.run(a,check=True,**kw)
def sha(x):return hashlib.sha256(x).hexdigest()
def sections(path):
 data=path.read_bytes();m={}
 if data[:4]==b'\x7fELF':
  assert data[4:6]==b'\x02\x01';off=struct.unpack_from('<Q',data,40)[0];sz,count,index=struct.unpack_from('<HHH',data,58)
  hdr=[struct.unpack_from('<IIQQQQIIQQ',data,off+sz*i)for i in range(count)]
  sym=hdr[index];strings=data[sym[4]:sym[4]+sym[5]]
  for name,typ,flags,addr,at,n,*_ in hdr:
   if flags&2 and typ!=8:
    section=strings[name:strings.index(b'\0',name)].decode();m[section]=[addr,n,sha(data[at:at+n])]
 else:
  assert data[:4]==b'\xcf\xfa\xed\xfe';count=struct.unpack_from('<I',data,16)[0];off=32
  for _ in range(count):
   cmd,n=struct.unpack_from('<II',data,off)
   if cmd==0x19:
    items=struct.unpack_from('<I',data,off+64)[0]
    for j in range(items):
     at=off+72+j*80
     field=lambda a:data[a:a+16].split(b'\0')[0].decode()
     name=field(at+16)+','+field(at);addr,size,start=struct.unpack_from('<QQI',data,at+32)
     flags=struct.unpack_from('<I',data,at+64)[0]
     if (flags&255) not in (1,12,18):m[name]=[addr,size,sha(data[start:start+size])]
   off+=n
 assert '.text' in m or '__TEXT,__text' in m
 return m
def symbols(path):
 sym=get('nm','-a',path)
 return sorted({k for k in ('modRMTable','x86PackedUIDs','modRMTableDirect')if any(line.split() and line.split()[-1].lstrip('_')==k for line in sym.splitlines())})
assert get('git','-C',src,'rev-parse','HEAD').strip()==q['base'] and get('git','-C',nd,'rev-parse','HEAD').strip()==q['dev']
w=Path(tempfile.mkdtemp());b=w/'build';proj=w/'project';proj.mkdir()
try:
 (proj/'cmake').mkdir();(proj/'third_party').mkdir();(proj/'third_party/capstone').symlink_to(src)
 name='cmake/NeverDCapstoneCompilerOptions.inc';(proj/name).write_text(get('git','-C',nd,'show',q['dev']+':'+name))
 top=get('git','-C',nd,'show',q['dev']+':CMakeLists.txt')
 (proj/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(Profile LANGUAGES C CXX)\n'+top[top.index('# --- Capstone (our fork'):top.index('# --- NeverD CMake helpers')])
 run('cmake','-G','Ninja','-S',proj,'-B',b,'-DCMAKE_BUILD_TYPE=Release','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON')
 (w/'main.c').write_text('#include <capstone/capstone.h>\nint main(void){csh h;const uint8_t op[]={0x66,0x0f,0x78,0xc0,1,2};cs_insn *i=0;if(cs_open(CS_ARCH_X86,CS_MODE_64,&h))return 3;size_t n=cs_disasm(h,op,sizeof(op),0,1,&i);if(n)cs_free(i,n);cs_close(&h);return n!=1;}\n')
 out={};cc=os.environ.get('CC','clang')
 for key in ('base','compact','canonical'):
  run('git','-C',src,'restore','--source','HEAD','--staged','--worktree','--','.')
  if key!='base':
   patch=r/(key+'.patch');assert sha(patch.read_bytes())==q[key]['sha256']
   run('git','-C',src,'apply','--index',patch);assert get('git','-C',src,'write-tree').strip()==q[key]['tree']
  run('cmake','--build',b,'--target','capstone_static','--parallel','4')
  objs={x.name:sha(x.read_bytes())for x in b.rglob('*.c.o')};assert {'PPCMapping.c.o','RISCVMapping.c.o','X86DisassemblerDecoder.c.o'}<=objs.keys()
  lib,=b.rglob('libcapstone.a');elf=w/'probe'
  args=['-Wl,-force_load,'+str(lib)] if platform.system()=='Darwin' else ['-Wl,--whole-archive',str(lib),'-Wl,--no-whole-archive','-no-pie','-lm']
  run(cc,'-O2','-I',src/'include',w/'main.c',*args,'-o',elf);run(elf)
  so=sections(elf);obj,=b.rglob('X86DisassemblerDecoder.c.o')
  command,=[x for x in rd(b/'compile_commands.json')if Path(x['file']).name=='X86DisassemblerDecoder.c']
  dbg=w/'debug.o';argv=shlex.split(command['command']);argv[argv.index('-o')+1]=str(dbg)
  run(*argv,'-O0','-g','-UNDEBUG',cwd=command['directory'])
  out[key]=dict(objects=objs,sections=so,release_tables=symbols(obj),debug_tables=symbols(dbg),debug_object_bytes=dbg.stat().st_size)
  save('images',out)
 assert out['canonical']['release_tables']==out['canonical']['debug_tables']==['modRMTable']
 assert out['compact']['release_tables']==['x86PackedUIDs']
 cmp={}
 for a,bk in [('base','compact'),('base','canonical'),('compact','canonical')]:
  x=out[a];y=out[bk];assert x['objects'].keys()==y['objects'].keys() and x['sections'].keys()==y['sections'].keys()
  delta=[k for k in x['objects']if x['objects'][k]!=y['objects'][k]]
  assert set(delta)<={'X86DisassemblerDecoder.c.o'}
  cmp[a+'/'+bk]=dict(objects=delta,changed_sections=[k for k,v in x['sections'].items()if v!=y['sections'][k]],changed_extents=[k for k,v in x['sections'].items()if v[:2]!=y['sections'][k][:2]])
 save('complete',dict(source=q,comparisons=cmp,debug_tables={k:v['debug_tables'] for k,v in out.items()},tested=platform.machine(),compiler=get(cc,'--version').splitlines()[0]))
finally:
 n=sum(f.stat().st_size for f in w.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
