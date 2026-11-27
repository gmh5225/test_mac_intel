"""Rebuild the actual Mapping.o after editing a native or per-slice header."""
from pathlib import Path
import hashlib,json,os,platform,subprocess as sp
def verify(src,build,cc,universal):
    digest=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    args=['make','-C',src,'CC='+cc,'CAPSTONE_ARCHS=arm','CAPSTONE_STATIC=yes','CAPSTONE_SHARED=no','CAPSTONE_BUILD_CORE_ONLY=yes','BUILDDIR='+str(build),'MACOS_UNIVERSAL='+('yes'if universal else'no')]
    obj=build/'obj/Mapping.o';unit=src/'Mapping.c';original=unit.read_bytes();headers=[src/'dep-probe-arm.h',src/'dep-probe-x86.h'];assert not any(p.exists()for p in headers)
    try:
        for p in headers:p.write_text('#define CAPSTONE_DEPENDENCY_PROBE 1\n')
        unit.write_bytes(original+b'\n#if defined(__aarch64__) || defined(__arm64__)\n#include "dep-probe-arm.h"\n#else\n#include "dep-probe-x86.h"\n#endif\nint cs_make_dependency_value(void);\nint cs_make_dependency_value(void) { return CAPSTONE_DEPENDENCY_PROBE; }\n')
        sp.run([*args,obj],check=True)
        deps={p.name:p.read_text()for p in obj.parent.glob('Mapping*.d')}
        if universal:
            assert len(deps)==2 and 'dep-probe-arm.h' in deps['Mapping.arm64.d'] and 'dep-probe-x86.h' in deps['Mapping.x86_64.d']
            chosen=headers
        else:
            chosen=[headers[0]if platform.machine().lower() in ('arm64','aarch64') else headers[1]]
            assert len(deps)==1 and chosen[0].name in deps['Mapping.d']
        for p in chosen:
            before=digest(obj);p.write_text('#define CAPSTONE_DEPENDENCY_PROBE 29\n');probe=sp.run([*args,'--question',obj]);assert probe.returncode==1,(probe.returncode,p)
            sp.run([*args,obj],check=True);after=digest(obj);assert after!=before
            obj.unlink();sp.run([*args,obj],check=True);assert digest(obj)==after
        assert sp.run([*args,'--question',obj]).returncode==0
        return dict(compiler=cc,universal=universal,slices=[p.name for p in chosen],depfiles=sorted(deps),matches_clean=True)
    finally:
        unit.write_bytes(original)
        for p in headers:p.unlink(missing_ok=True)
