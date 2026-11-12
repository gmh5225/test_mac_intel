from pathlib import Path
import hashlib,subprocess as sp

def install(baseline,candidate,tools,work):
    driver=work/'gen-fixed-records'
    sp.run(['clang++','-std=c++17','-O2','-I',str(baseline/'include'),str(tools/'generate.cpp'),str(work/'base-build/libcapstone.a'),'-o',str(driver)],check=True)
    result=sp.run([driver],stdout=sp.PIPE,stderr=sp.PIPE,check=True)
    arch=candidate/'arch/X86';(arch/'X86GenFixedOutput.inc').write_bytes(result.stdout)
    header=arch/'X86Disassembler.h';s=header.read_text();a=s.index('bool X86_getInstruction(')
    define='''#if defined(CAPSTONE_HAS_X86) && !defined(CAPSTONE_DIET) && !defined(CAPSTONE_X86_REDUCE) && defined(CAPSTONE_USE_SYS_DYN_MEM) && !defined(CAPSTONE_HAS_OSXKERNEL) && !defined(_KERNEL_MODE) && !defined(_WIN32_WCE)
#define CAPSTONE_X86_FIXED_OUTPUT
bool X86_tryFixedOutput(cs_struct *handle, uint8_t opcode, cs_insn *insn,
			uint16_t *insn_size);
#endif

'''
    header.write_text(s[:a]+define+s[a:])
    f=arch/'X86Disassembler.c';s=f.read_text();a=s.index('// Public interface for the disassembler')
    addition='#ifdef CAPSTONE_X86_FIXED_OUTPUT\n#include "X86InstPrinter.h"\n'+(tools/'records.hfrag').read_text()+'\n#include "X86GenFixedOutput.inc"\n\n'+(tools/'dispatch.cfrag').read_text()+'#endif\n\n'
    f.write_text(s[:a]+addition+s[a:])
    f=candidate/'cs.c';s=f.read_text();old='\tif (handle->arch == CS_ARCH_X86)\n\t\tMCInst_InitX86(&mci);\n\telse'
    assert s.count(old)==1
    f.write_text(s.replace(old,'''	if (handle->arch == CS_ARCH_X86) {
#ifdef CAPSTONE_X86_FIXED_OUTPUT
		if (size && X86_tryFixedOutput(handle, code[0], insn, insn_size))
			return true;
#endif
		MCInst_InitX86(&mci);
	} else'''))
    return dict(bytes=len(result.stdout),sha256=hashlib.sha256(result.stdout).hexdigest(),summary=result.stderr.decode().strip())
