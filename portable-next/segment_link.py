from pathlib import Path
import os,subprocess as sp,sys
def segment(src,bench,b,t,profile,label,run,linkage):
    shared=linkage=='shared'
    if os.name=='nt':
        lib=b/('capstone.lib' if shared else 'capstone_static.lib')
        out=(b if shared else t)/'segment.exe'
        runtime='/MT' if 'CAPSTONE_BUILD_STATIC_MSVC_RUNTIME:BOOL=ON' in (b/'CMakeCache.txt').read_text() else '/MD'
        args=['cl','/nologo','/O2',runtime,'/EHsc','/std:c++17','/I'+str(src/'include'),'/I'+str(src),bench/'segment.cpp',lib,'/Fo:'+str(t/'segment.obj'),'/Fe:'+str(out)]
    else:
        lib=b/(('libcapstone.dylib' if sys.platform=='darwin' else 'libcapstone.so') if shared else 'libcapstone.a')
        out=t/'segment'
        args=['g++' if profile=='gcc' else 'clang++','-std=c++17','-O2','-I',src/'include','-I',src,bench/'segment.cpp',lib,*(['-Wl,-rpath,'+str(b)] if shared else []),'-o',out]
    assert lib.is_file()
    run(label+'-segment-link',*args)
    process=sp.run([out],capture_output=True,text=True)
    assert process.returncode==0,(label,process.returncode,process.stderr[-2000:])
    counts=list(map(int,process.stdout.split()))
    assert counts==[884736, 405504, 12422393723512408869],(label,counts)
    return counts
