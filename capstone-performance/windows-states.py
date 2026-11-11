from pathlib import Path
import subprocess as s,tempfile,json,hashlib,os,shutil,sys
d=Path(__file__).resolve().parent;ev=Path('capstone-evidence').resolve();ev.mkdir(exist_ok=True)
def run(a,cwd=None):s.run(a,check=True,cwd=cwd)
def main(work):
 src=work/'src';ref='7b209eb13c8e0f9915307320016e8a1cecd12253'
 run(['git','-c','core.autocrlf=false','init',src]);run(['git','config','core.autocrlf','false'],src)
 run(['git','fetch','-q','--depth=1','https://github.com/NeverSight/capstone',ref],src);run(['git','checkout','--detach','-q','FETCH_HEAD'],src)
 patch=d/'windows-formatter.patch'
 assert hashlib.sha256(patch.read_bytes()).hexdigest()==json.loads((d/'manifest.json').read_text())['source_lineage'][patch.name]['sha256']
 run(['git','apply',patch],src)
 q=src/'SStream.c';t=q.read_text();i=t.index('CAPSTONE_INTERNAL void SStream_concat0_substr(');t=t[:i]+'unsigned direct_count, heap_count;\nint previous_direct(void) { return cs_mem_malloc == malloc && cs_mem_free == free; }\n'+t[i:];i=t.index('if (default_allocator) {');j=t.index('char *substr = cs_mem_malloc',i);t=t[:i]+t[i:j].replace('if (default_allocator) {','if (default_allocator) {\n\t\t++direct_count;')+'++heap_count;\n\t'+t[j:];q.write_text(t)
 with (src/'CMakeLists.txt').open('a') as f:f.write("""
add_executable(path_states "${EVIDENCE_SOURCE}/path-states.c")
add_executable(hook_pairs "${EVIDENCE_SOURCE}/hook-pairs.c")
foreach(t path_states hook_pairs)
 target_compile_features(${t} PRIVATE c_std_11)
 target_link_libraries(${t} PRIVATE capstone_static)
 target_include_directories(${t} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/arch/X86" "${CMAKE_BINARY_DIR}")
 target_compile_definitions(${t} PRIVATE CAPSTONE_HAS_X86 CAPSTONE_USE_SYS_DYN_MEM)
 if(CAPSTONE_X86_REDUCE)
  target_compile_definitions(${t} PRIVATE CAPSTONE_X86_REDUCE)
 endif()
endforeach()
""")
 sys.path.insert(0,str(src/'suite/synctools'))
 from x86_operand_specializations import translation_specializations,read_sets
 x=src/'arch/X86';fn=(x/'X86DisassemblerTranslator.h').read_text().split('X86_TRANSLATE_INLINE bool translateInstruction(',1)[1].split('#undef X86_TRANSLATE_INLINE')[0]
 for suffix in ('','_reduce'):
  b=work/('build'+suffix);b.mkdir();table=x/('X86GenDisassemblerTables'+suffix+'.inc');enabled={i for i,_ in translation_specializations(suffix)}
  n=len(read_sets(table,include_duplicates=True));(b/'descriptors.inc').write_text(table.read_text().split('static const uint8_t x86DisassemblerContexts',1)[0]+'\nstatic const unsigned char affected[] = {'+','.join('1' if i in enabled else '0' for i in range(n))+'};\n')
  (b/'paths.inc').write_text('\n'.join('static bool '+name+'('+fn.replace('#if !defined(_MSC_VER) || defined(__clang__)','#if '+str(v)) for v,name in [(1,'generatedSwitch'),(0,'descriptorLoop')]))
  run(['cmake','-S',src,'-B',b,'-G','Visual Studio 17 2022','-A','x64','-DEVIDENCE_SOURCE='+d.as_posix(),'-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_X86_REDUCE='+('ON' if suffix else 'OFF')])
  run(['cmake','--build',b,'--config','Release','--parallel','4','--target','path_states','hook_pairs'])
  for name in ('path_states','hook_pairs'):
   out=s.check_output([b/('Release/'+name+'.exe')],text=True);(ev/(name+suffix+'.log')).write_text(out);print(out,flush=True)
with tempfile.TemporaryDirectory(dir=os.environ['RUNNER_TEMP'],ignore_cleanup_errors=True) as tmp:main(Path(tmp))
