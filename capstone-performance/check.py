from pathlib import Path
import hashlib
import os
import shutil
import subprocess as sp
import sys
import tempfile
d=Path(__file__).resolve().parent
e=Path('capstone-evidence').resolve()
e.mkdir(exist_ok=True)
x='arch/X86/X86DisassemblerDecoder.c'
def run(argv,cwd):
    print(' '.join(map(str,argv)),flush=True)
    sp.run(argv,cwd=cwd,check=True)
def verify(w):
    src=w/'source';src.mkdir()
    run(['git','init','-q'],src)
    run(['git','fetch','-q','--depth=1','https://github.com/NeverSight/capstone','a60be2e71f73739659fd895009263e0f276e9d22'],src)
    run(['git','checkout','-q','--detach','FETCH_HEAD'],src)
    for f in ('combined.patch',):
        assert hashlib.sha256((d/f).read_bytes()).hexdigest() == (d/(f+'.sha256')).read_text().strip()
    (w/'main.c').write_text('int test_terminal_states(void);\nint main(void) { return test_terminal_states(); }\n')
    with (src/'CMakeLists.txt').open('a') as f:
        f.write('\nadd_executable(terminal_states "'+str(w/'main.c')+'")\ntarget_link_libraries(terminal_states PRIVATE capstone_static)\n')
    b=w/'build'
    run(['cmake','-G','Ninja','-S',src,'-B',b,'-DCMAKE_C_COMPILER=clang','-DCMAKE_CXX_COMPILER=clang++','-DCMAKE_BUILD_TYPE=RelWithDebInfo','-DCMAKE_C_FLAGS_RELWITHDEBINFO=-O1 -gline-tables-only -DNDEBUG','-DCMAKE_C_FLAGS=-fsanitize=memory -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer -fPIE','-DCMAKE_EXE_LINKER_FLAGS=-pie -fsanitize=memory','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_X86_REDUCE='+sys.argv[1]],w)
    reference=None
    for name in ('base', 'combined'):
        run(['git','restore','--source=HEAD','--',x,'arch/X86/X86GenLegacyTerminal.inc','suite/synctools/x86_operand_specializations.py'],src)
        if name!='base':run(['git','apply',d/(name+'.patch')],src)
        if name=='combined': (src/x).write_text('#define X86_NATIVE_SCAN_EXTENT\n'+(src/x).read_text())
        with (src/x).open('a') as f:f.write('\n#include "'+str(d/'check.c')+'"\n')
        run(['cmake','--build',b,'--parallel','4','--target','terminal_states'],w)
        env=dict(os.environ,MSAN_OPTIONS='halt_on_error=1:exit_code=94:symbolize=1')
        res=sp.run([b/'terminal_states'],env=env,stdout=sp.PIPE,stderr=sp.STDOUT,text=True)
        (e/(name+'.txt')).write_text(res.stdout);print(res.stdout,flush=True);res.check_returncode()
        if reference is None:reference=res.stdout
        else:assert res.stdout==reference
with tempfile.TemporaryDirectory(dir=os.environ['RUNNER_TEMP']) as tmp:verify(Path(tmp))
