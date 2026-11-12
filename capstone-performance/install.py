from pathlib import Path
import hashlib,subprocess

def install(baseline, candidate, tools, work):
    driver=work/'generate-fixed-output'
    subprocess.run(['clang','-std=c11','-O2','-I',str(baseline/'include'),str(tools/'generate.c'),str(work/'base-build/libcapstone.a'),'-o',str(driver)],check=True)
    rows=subprocess.check_output([driver])
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
    s=s[:at]+'''#ifdef CS_FIXED_X86_OUTPUT
	if (handle->arch == CS_ARCH_X86 && size) {
		const unsigned slot = fixed_index[handle->mode == CS_MODE_64][code[0]];
		if (slot && (handle->mode == CS_MODE_32 || handle->mode == CS_MODE_64) &&
		    !handle->no_text && !handle->imm_unsigned && !handle->mnem_list &&
		    (handle->syntax == CS_OPT_SYNTAX_DEFAULT || handle->syntax == CS_OPT_SYNTAX_INTEL) &&
		    handle->disasm == X86_getInstruction && handle->printer == X86_Intel_printInst &&
		    handle->post_printer == X86_postprinter && !handle->doing_mem && cs_vsnprintf == cs_default_vsnprintf) {
			*insn_size = insn->size = 1;
			insn->id = fixed_records[slot].id;
			insn->bytes[0] = code[0];
			memcpy(insn->mnemonic, fixed_records[slot].mnemonic, sizeof(insn->mnemonic));
			memcpy(insn->op_str, fixed_records[slot].operands, sizeof(insn->op_str));
			if (insn->detail)
				memcpy(insn->detail, fixed_records[slot].detail, sizeof(fixed_records[slot].detail));
			return true;
		}
	}
#endif
'''+s[at:]
    f.write_text(s)
    return dict(generated_bytes=len(rows),sha256=hashlib.sha256(rows).hexdigest(),fixed_records=rows.count(b'\n{')-2)
