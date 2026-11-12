from pathlib import Path
import hashlib, shutil, subprocess


def install(baseline, candidate, tools, work):
    binary = work / 'generate-x86-simple-output'
    subprocess.run(['clang++', '-std=c++17', '-O2', '-I', baseline/'include', tools/'generate.cpp',
                    work/'base-build/libcapstone.a', '-o', binary],check=True)
    result = subprocess.run([binary],capture_output=True,check=True)
    arch = candidate/'arch/X86'
    shutil.copyfile(tools/'X86SimpleOutput.h',arch/'X86SimpleOutput.h')
    (arch/'X86GenSimpleOutput.inc').write_bytes(result.stdout)
    generator = (tools/'generate.cpp').read_text().replace('#include "X86SimpleOutput.h"','#include "../../arch/X86/X86SimpleOutput.h"')
    (candidate/'suite/synctools/x86_simple_output.cpp').write_text(generator)
    header=arch/'X86Disassembler.h';text=header.read_text();anchor='bool X86_getInstruction('
    declaration='''#if !defined(CAPSTONE_DIET) && !defined(CAPSTONE_X86_REDUCE) && \\
	defined(CAPSTONE_USE_SYS_DYN_MEM) && !defined(CAPSTONE_HAS_OSXKERNEL) && \\
	!defined(_KERNEL_MODE) && !defined(_WIN32_WCE)
#define CAPSTONE_X86_SIMPLE_OUTPUT
#include "../../cs_priv.h"
CAPSTONE_INTERNAL bool X86_trySimpleOutput(cs_struct *handle, const uint8_t *code,
					 size_t size, cs_insn *insn,
					 uint16_t *insn_size);
#endif

'''
    assert text.count(anchor)==1;header.write_text(text.replace(anchor,declaration+anchor))
    decoder=arch/'X86Disassembler.c';text=decoder.read_text();anchor='// Public interface for the disassembler'
    add='#ifdef CAPSTONE_X86_SIMPLE_OUTPUT\n#include "X86InstPrinter.h"\n#include "X86SimpleOutput.h"\n#include "X86GenSimpleOutput.inc"\n\n'+(tools/'dispatch.cfrag').read_text()+'#endif\n\n';assert text.count(anchor)==1;decoder.write_text(text.replace(anchor,add+anchor))
    f=candidate/'cs_disasm_internal.h';text=f.read_text();old='\treturn cs_decode_full_insn(handle, code, size, insn, insn_size, batch);';assert text.count(old)==1
    f.write_text(text.replace(old,'''#ifdef CAPSTONE_X86_SIMPLE_OUTPUT
	if (handle->arch == CS_ARCH_X86 && size &&
	    X86_trySimpleOutput(handle, code, size, insn, insn_size))
		return true;
#endif
'''+old))
    return dict(bytes=len(result.stdout),sha256=hashlib.sha256(result.stdout).hexdigest(),summary=result.stderr.decode().strip())
