from pathlib import Path
import gzip,hashlib,json,os,platform,re,shutil,subprocess as sp,tempfile
import corpus
from geometry import Geometry
from section_identity import capture as capture_reader, compare as compare_reader
from jpeg_fixture import prepare_jpeg
r=Path(__file__).resolve().parent;e=r.parent/'evidence';e.mkdir();s=r.parent/'source';cc=os.environ['MEASURE_CC']
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def write(n,v):(e/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def run(args,label,cwd=None):
 print(label,flush=True)
 with (e/(label+'.log')).open('w') as f:rc=sp.run(list(map(str,args)),cwd=cwd,stdout=f,stderr=sp.STDOUT).returncode
 if rc:raise RuntimeError((label,(e/(label+'.log')).read_text()[-1300:]))
assert sp.check_output(['git','-C',s,'rev-parse','HEAD'],text=True).strip()==json.loads((r/'manifest.json').read_text())['capstone_revision']
with tempfile.TemporaryDirectory(prefix='capstone-shared-iterator-cost-') as tmp:
 t=Path(tmp);b=t/'build'
 try:
  import re
  mapping=(s/'arch/ARM/ARMGenCSMappingInsn.inc').read_text()
  rows=re.findall(r'^\s*(ARM_[\w]+) /\* (\d+) \*/, (ARM_INS_[\w]+)',mapping,re.M)
  enums=dict(re.findall(r'^\s*(ARM_[\w]+)\s*=\s*(\d+)',(s/'arch/ARM/ARMGenInstrInfo.inc').read_text(),re.M))
  assert [int(row[1]) for row in rows]==list(range(4465)) and all(enums[name]==idx for name,idx,_ in rows)
  write('mapping',dict(rows=len(rows),sha256=hashlib.sha256(mapping.encode()).hexdigest()))
  if Path('/proc/cpuinfo').exists():
   write('cpu',{'model':next(x.split(':',1)[1].strip() for x in Path('/proc/cpuinfo').read_text().splitlines() if x.startswith(('model name','CPU part')))})
  mixed=os.environ['BUILD_ARCHS']=='four';assert mixed
  all_inputs=corpus.prepare(r,t,e,run)
  all_inputs.append(prepare_jpeg(r,t,e,run))
  choices={'arm64-ls','mips64el-ls','jpeg-avx2-i386'}
  cases=[x for x in all_inputs if x['name'] in choices];assert len(cases)==len(choices)

  run(['clang++','-O3','-DNDEBUG','-std=c++17','-I',s,'-I',s/'include','-c',r/'single.cpp','-o',t/'single.o'],'consumer')
  run(['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_ARM_SUPPORT=ON',*(['-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_MIPS_SUPPORT=ON','-DCAPSTONE_AARCH64_SUPPORT=ON'] if mixed else []),'-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF'],'configure')
  units=['x86_simple_output','x86_reg_access','detail_option','text_option','x86_encoding_accuracy','x86_scan_batch','x86_buffer_bounds','x86_printer_prechecked']
  bins={};objects={};libs={};ownedlibs={}
  geometry=Geometry(e)
  write('compiler',dict(compiler=sp.check_output([cc,'--version'],text=True)))
  libname='libcapstone.dylib' if platform.system()=='Darwin' else 'libcapstone.so'
  reader_views={}
  for key in ('base','packed','scan'):
   variant=r/('baseline.patch' if key=='base' else key+'.patch')
   if key!='base':
    run(['git','apply',variant],'apply-'+key,s)
    run(['git','add','-A'],'stage-tested-source-'+key,s)
    tested=sp.check_output(['git','write-tree'],cwd=s,text=True).strip()
    assert tested==json.loads((r/('candidate.json' if key=='scan' else 'input.json')).read_text())['tree'],tested
    write('tested-source-'+key,dict(tree=tested,patch_sha256=sha(variant)))
    run(['git','reset','-q'],'unstage-tested-source-'+key,s)
   run(['cmake','--build',b,'--target','capstone_static','capstone_shared',*units,'--parallel','4'],'build-'+key)
   run(['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(units)+')$'],'units-'+key)
   assert '100% tests passed, 0 tests failed out of 8' in (e/('units-'+key+'.log')).read_text()
   link=t/'single';run(['clang++',t/'single.o',b/'libcapstone.a','-lm','-o',link],'link-'+key);f=t/key;link.rename(f);bins[key]=f
   (e/(key+'-symbols.txt')).write_bytes(sp.check_output(['nm','-n','-S','--defined-only',f]))
   (e/(key+'-sections.txt')).write_bytes(sp.check_output(['readelf','-WS',f]))
   geometry.capture(key,b,f)
   objdir=b/'CMakeFiles/capstone.dir'
   objects[key]={str(v.relative_to(objdir)):sha(v) for v in objdir.rglob('*.o')}
   if key!='base':reader_views[key]=capture_reader(objdir/'arch/X86/X86VexScan.c.o','.text' if key=='packed' else '.cs_x86_vex_scan')
   libs[key]=t/(key+'-'+libname);shutil.copy2(b/libname,libs[key])
   if key!='base':run(['git','apply','-R',variant],'restore-'+key,s)
  for key in ('packed','scan'):
   changed=[k for k,h in objects['base'].items()if objects[key].get(k)!=h]
   added=set(objects[key])-set(objects['base'])
   assert added=={'arch/X86/X86VexScan.c.o'},added
   assert set(objects['base']) <= set(objects[key])
   assert set(changed) == {'arch/X86/X86DisassemblerDecoder.c.o'},changed
   active=bool(changed)
   write('scope-'+key,dict(active=active,source_applies=True,policy='Shared packed C5 reader with or without private ELF code/data sections; old runtime objects identical between candidates'))
   write('objects-'+key,dict(changed=changed,added=sorted(added),identical=len(objects['base'])-len(changed)))
  assert all(objects['packed'][name]==objects['scan'][name] for name in objects['base'])
  write('reader-section-identity',dict(compare_reader(reader_views['packed'],reader_views['scan']),old_runtime_objects_identical=len(objects['base'])))
  geometry.finish()
  write('binaries',{key:sha(path) for key,path in bins.items()})
  write('valgrind',dict(version=sp.check_output(['valgrind','--version'],text=True)))
  if hasattr(os,'sched_getaffinity'):os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
  data=[]
  for x in cases:
   for mode in ((0,2) if x['name']=='arm64-ls' else (0,) if x['name']=='jpeg-avx2-i386' else (2,)):
    reference=None
    for key in ('base','packed','scan'):
     label=x['name']+'-'+str(mode)+'-'+key
     tail=list(map(str,[x['selector'],mode,x['path'],1]))
     native=json.loads(sp.check_output([str(bins[key]),*tail],text=True))
     if reference is None:reference=(native['first'],native['result'])
     assert reference==(native['first'],native['result'])
     raw=t/(label+'.callgrind')
     run(['valgrind','--tool=callgrind','--cache-sim=yes','--branch-sim=yes','--dump-instr=yes','--collect-jumps=yes','--collect-atstart=no','--callgrind-out-file='+str(raw),bins[key],*tail],label)
     log=(e/(label+'.log')).read_text()
     measured=json.loads(next(line for line in log.splitlines() if line.startswith('{')))
     assert reference==(measured['first'],measured['result'])
     content=raw.read_text()
     events=next(line[8:].split() for line in content.splitlines() if line.startswith('events: '))
     counts=list(map(int,next(line[9:].split() for line in content.splitlines() if line.startswith('summary: '))))
     assert len(events)==len(counts) and counts[0]>0
     row=dict(case=x['name'],mode=mode,variant=key,events=dict(zip(events,counts)),result=measured['result'],captured_traversals=1,warm_traversals=2)
     data.append(row);write('instruction-costs',data)
     with gzip.open(e/(label+'.callgrind.gz'),'wb')as stream:stream.write(raw.read_bytes())
     run(['callgrind_annotate','--inclusive=no','--threshold=100','--show=Ir,Dr,Dw','--auto=no',raw],label+'-self')
     raw.unlink()
  assert len(data)==12
  write('complete',dict(rows=len(data),cc=cc,host=platform.platform(),native_qualification=False,scope='Deterministic dynamic instruction and memory counts; simulated cache counters do not establish native hardware behavior.'))
 finally:
  n=sum(f.stat().st_size for f in t.rglob('*')if f.is_file());shutil.rmtree(t);write('cleanup',dict(bytes=n,removed=not t.exists()))
