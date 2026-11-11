from pathlib import Path
import subprocess as s,tempfile,json,hashlib,os,shutil,sys
d=Path(__file__).resolve().parent;ev=Path('capstone-evidence').resolve();ev.mkdir(exist_ok=True)
def run(a,cwd=None):s.run(a,check=True,cwd=cwd)
def main(work):
 src=work/'src';ref='3b4aeea8566a118cca94ef00fb4f16c39c53a29a'
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
 for toolset in ('MSVC','ClangCL'):
  b=work/toolset
  cmake=['cmake','-S',src,'-B',b,'-G','Visual Studio 17 2022','-A','x64']
  if toolset=='ClangCL':cmake+=['-T','ClangCL']
  run(cmake+['-DEVIDENCE_SOURCE='+d.as_posix(),'-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON'])
  run(['cmake','--build',b,'--config','Release','--parallel','4','--target','hook_pairs'])
  out=s.check_output([b/'Release/hook_pairs.exe'],text=True);(ev/(toolset+'-hooks.log')).write_text(out);print(out,flush=True)
  for line in out.splitlines():
   if 'default-built-in' in line or 'built-in' in line or 'explicit CRT' in line:
    assert 'direct 1 heap 0' in line, line
   else:
    assert 'direct 0 heap 1' in line,line
with tempfile.TemporaryDirectory(dir=os.environ['RUNNER_TEMP'],ignore_cleanup_errors=True) as tmp:main(Path(tmp))
