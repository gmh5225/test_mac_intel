"""Observe GCC's exact optimizer decisions; never time a diagnostic rebuild."""
from pathlib import Path
import gzip,hashlib,json,os,re,shlex,shutil,subprocess as sp,tempfile

r=Path(__file__).resolve().parent;root=r.parent;evidence=root/'evidence';evidence.mkdir()
reference='729680277dd762704ea3270291b7a75318f51583'
def save(name,value):(evidence/(name+'.json')).write_text(json.dumps(value,indent=2)+'\n')
def run(args,label,cwd=None):
 print(label,flush=True)
 with (evidence/(label+'.log')).open('w') as out:sp.run(list(map(str,args)),cwd=cwd,stdout=out,stderr=sp.STDOUT,check=True)
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
work=Path(tempfile.mkdtemp(prefix='capstone-vex-inline-'))
try:
 source=work/'source';build=work/'build'
 run(['git','clone','-q','--shared',root/'source',source],'clone')
 run(['git','checkout','-q','--detach',reference],'checkout',source)
 save('compiler',dict(version=sp.check_output(['gcc','--version'],text=True),purpose='Compiler decision diagnosis; no native timing or publication qualification.'))
 flags=['-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON',
        '-DCMAKE_C_COMPILER=gcc','-DCMAKE_C_FLAGS_RELEASE=-O3 -DNDEBUG -fomit-frame-pointer -Wno-error=discarded-qualifiers',
        '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',*['-DCAPSTONE_'+a+'_SUPPORT=ON'for a in ['X86','ARM','AARCH64','MIPS']],
        '-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_SHARED_LIBS=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON',
        '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF']
 run(['cmake','-S',source,'-B',build,*flags],'configure')
 for label in ['integer','output','leaf','local','opaque']:
  if label!='integer':run(['git','apply',r/('dispatch.patch'if label in ('output','leaf','local')else 'scan.patch')],'apply-'+label,source)
  if label=='leaf':
   path=source/'arch/X86/X86VexScan.h';text=path.read_text();marker='CAPSTONE_INTERNAL CS_PRESERVE_MOST int'
   assert text.count(marker)==1;path.write_text(text.replace(marker,'__attribute__((leaf))\n'+marker))
  if label=='local':
   path=source/'arch/X86/X86DisassemblerDecoder.c';text=path.read_text()
   marker='const int status =\n\t\t\tX86_scanVex32PublicPlan(code, code_len, result);'
   assert text.count(marker)==1
   text=text.replace(marker,'X86ScanResult local_result;\n\t\tconst int status = X86_scanVex32PublicPlan(code, code_len, &local_result);\n\t\tif (status == X86_SCAN_COMPLETE) *result = local_result;')
   path.write_text(text)
  if label=='opaque':
   path=source/'arch/X86/X86VexScan.h';text=path.read_text();assert text.count('__attribute__((pure))')==1
   path.write_text(text.replace('__attribute__((pure))',''))
  run(['cmake','--build',build,'--target','capstone_static','--parallel','4'],'build-'+label)
  obj=build/'CMakeFiles/capstone.dir/arch/X86/X86DisassemblerDecoder.c.o'
  entries=json.loads((build/'compile_commands.json').read_text());entry,=[v for v in entries if Path(v['file']).name=='X86DisassemblerDecoder.c']
  args=entry.get('arguments')or shlex.split(entry['command']);diagnostic=work/'diagnostic.o';args[args.index('-o')+1]=str(diagnostic)
  dumps={key:work/(label+'-'+key+'.txt')for key in ['einline','inline','unswitch','alias','optimized','modref']}
  args.extend(['-fdump-tree-einline-details='+str(dumps['einline']),'-fdump-ipa-inline-details='+str(dumps['inline']),'-fdump-tree-unswitch-details='+str(dumps['unswitch']),'-fdump-tree-alias-details='+str(dumps['alias']),'-fdump-tree-optimized='+str(dumps['optimized']),'-fdump-ipa-modref='+str(dumps['modref'])])
  run(args,'diagnose-'+label,entry['directory']);assert sha(obj)==sha(diagnostic),'diagnostic flags changed code'
  metadata={}
  for key,path in dumps.items():
   text=path.read_text();metadata[key]=dict(sha256=sha(path),bytes=path.stat().st_size)
   if key in ('inline','modref'):
    with gzip.open(evidence/(label+'-ipa-'+key+'.txt.gz'),'wt')as out:out.write(text)
    events=[line for line in text.splitlines()if re.search('Inlin|inlin|size|growth',line)and any(name in line for name in ['X86_scanBatch','decodeScanResult','readVex','scanVex','decodeVex','decodeLegacy','consumeByte'])]
    save(label+'-'+key+'-events',events)
   else:
    blocks={}
    for name in ['X86_scanBatch','decodeScanResultFallback','decodeScanResultGeneric']:
     match=re.search(r'^;; Function '+name+r'\b.*?(?=^;; Function |\Z)',text,re.M|re.S)
     if match:
      block=match[0];blocks[name]=dict(bytes=len(block),sha256=hashlib.sha256(block.encode()).hexdigest())
      with gzip.open(evidence/(label+'-'+key+'-'+name+'.txt.gz'),'wt')as out:out.write(block)
    metadata[key]['functions']=blocks
   path.unlink()
  save(label+'-optimizer',dict(timed_object_unchanged=True,object_sha256=sha(obj),diagnostic_sha256=sha(diagnostic),dumps=metadata))
  (evidence/(label+'-symbols.txt')).write_bytes(sp.check_output(['nm','-S','--defined-only',obj]))
  with gzip.open(evidence/(label+'-decoder.asm.gz'),'wb')as out:out.write(sp.check_output(['objdump','-dr',obj]))
  diagnostic.unlink()
  run(['git','reset','--hard',reference],'restore-'+label,source);run(['git','clean','-fdx'],'clean-'+label,source)
 save('complete',dict(variants=5,exact_object_identity=True,native_qualification=False))
finally:
 files=[v for v in work.rglob('*')if v.is_file()];size=sum(v.stat().st_size for v in files)
 shutil.rmtree(work);save('cleanup',dict(removed=not work.exists(),bytes=size,files=len(files)))
