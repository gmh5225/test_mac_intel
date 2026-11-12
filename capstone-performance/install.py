from pathlib import Path
import hashlib,subprocess

def install(baseline, candidate, tools, work):
    driver=work/'generate-fixed-output'
    subprocess.run(['clang++','-std=c++17','-O2','-I',str(baseline/'include'),str(tools/'generate.cpp'),str(work/'base-build/libcapstone.a'),'-o',str(driver)],check=True)
    result=subprocess.run([driver],stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
    rows=result.stdout
    print(result.stderr.decode(),flush=True)
    name='X86FixedOutputExperiment.inc'
    (candidate/name).write_bytes(rows)
    f=candidate/'cs.c';s=f.read_text()
    at=s.index('#if defined(_MSC_VER)',s.index('static inline void fill_insn('))
    s=s[:at]+'''#if defined(CAPSTONE_HAS_X86) && !defined(CAPSTONE_DIET) && !defined(CAPSTONE_X86_REDUCE) && defined(CAPSTONE_USE_SYS_DYN_MEM) && !defined(CAPSTONE_HAS_OSXKERNEL) && !defined(_KERNEL_MODE) && !defined(_WIN32_WCE)
#define CS_FIXED_X86_OUTPUT
#include "arch/X86/X86InstPrinter.h"
#include "arch/X86/X86Disassembler.h"
#include "X86FixedOutputExperiment.inc"
#endif

'''+s[at:]
    at=s.index('\tMCInst mci;',s.index('cs_decode_full_insn(cs_struct'))
    s=s[:at]+(tools/'dispatch.cfrag').read_text()+s[at:]
    f.write_text(s)
    return dict(generated_bytes=len(rows),sha256=hashlib.sha256(rows).hexdigest(),qualified=result.stderr.decode().strip())
