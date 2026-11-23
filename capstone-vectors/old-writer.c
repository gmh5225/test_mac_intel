/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include "../../cs_priv.h"
#if defined(CAPSTONE_HAS_X86) && !defined(CAPSTONE_DIET) && \
	!defined(CAPSTONE_X86_REDUCE) && defined(CAPSTONE_USE_SYS_DYN_MEM) && \
	!defined(CAPSTONE_HAS_OSXKERNEL) && !defined(_KERNEL_MODE) && \
	!defined(_WIN32_WCE)
#if defined(__ELF__) && defined(__clang__)
#pragma clang section text = ".cs_x86_vex_memory_text" rodata = \
	".cs_x86_vex_memory_rodata"
#endif
#include "../../cs_disasm_internal.h"
#include "X86OutputOptions.h"
#include "X86SimpleOutput.h"
#include "X86GenSimpleOutput.inc"
#include "X86VexBaseMemory.h"

CAPSTONE_INTERNAL CS_PRESERVE_MOST bool
X86_decodeVexMemoryOrFull(cs_struct *handle, const uint8_t *code, size_t size,
			  cs_insn *insn, uint16_t *insn_size, bool batch)
{
	if ((code[0] & 0xfe) == 0xc4) {
		const unsigned prefix = code[0] == 0xc5 ? 2 : 3;
		if (size >= prefix + 2 && code[prefix + 1] < 0xc0 &&
		    !X86_OUTPUT_UNSUPPORTED(handle, false) &&
		    writeVexBaseMemory(code, size, prefix, insn, insn_size,
				       x86_simple_registers[3]))
			return true;
	}
	return cs_decode_full_insn(handle, code, size, insn, insn_size, batch);
}
#endif
