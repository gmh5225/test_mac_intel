unsigned long long bare_opcode_hits[256];
#if __has_include("arch/X86/X86GenDoubleShift32.inc")
/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifdef CAPSTONE_HAS_X86
#if defined(__ELF__) && defined(__clang__)
#pragma clang section text = ".cs_x86_register_fallback32_text" rodata = \
	".cs_x86_register_fallback32_rodata"
#endif
#include "../../cs_priv.h"
#if !defined(CAPSTONE_DIET) && !defined(CAPSTONE_X86_REDUCE) && \
	defined(CAPSTONE_USE_SYS_DYN_MEM) && \
	!defined(CAPSTONE_HAS_OSXKERNEL) && !defined(_KERNEL_MODE) && \
	!defined(_WIN32_WCE)
#include "X86OutputOptions.h"
#include "X86RegisterImmediateOutput.h"
#include "X86GenTest32Registers.inc"
#include "X86GenDoubleShift32.inc"
#include "../../cs_disasm_internal.h"

/* The caller checked the complete 0F A4/AC register encoding. */
static void writeDoubleShift32(const uint8_t *code, cs_insn *insn,
			       uint16_t *insn_size)
{
	const unsigned opcode = code[1], mr = code[2];
	const struct X86SimpleOutput *row = &double_shift32_rows[(opcode >> 3) & 1];
	const struct X86SimpleRegister *dst = &test32_regs[1][mr & 7];
	const struct X86SimpleRegister *src = &test32_regs[1][(mr >> 3) & 7];
	insn->id = row->id;
	insn->size = *insn_size = 4;
	memcpy(insn->bytes, code, 4);
	memset(insn->mnemonic, 0, sizeof(insn->mnemonic));
	memcpy(insn->mnemonic, row->mnemonic, sizeof(row->mnemonic));
	memset(insn->op_str, 0, sizeof(insn->op_str));
	char *out = insn->op_str;
	memcpy(out, dst->name, sizeof(dst->name));
	out += dst->length;
	memcpy(out, ", ", 2);
	out += 2;
	memcpy(out, src->name, sizeof(src->name));
	out += src->length;
	memcpy(out, ", ", 2);
	writeUnsignedImmediate(out + 2, code[3]);
	if (insn->detail) {
		X86_writeSimpleDetail(insn->detail, row, 0x0f, 0, mr,
				      dst->reg, src->reg);
		cs_x86 *x = &insn->detail->x86;
		x->opcode[1] = (uint8_t)opcode;
		x->operands[2].type = X86_OP_IMM;
		x->operands[2].imm = code[3];
		x->operands[2].size = 1;
		x->op_count = 3;
	}
}

CAPSTONE_INTERNAL CS_PRESERVE_MOST bool
X86_decodeRegisterFallback32(cs_struct *handle, const uint8_t *code,
			     size_t size, cs_insn *insn, uint16_t *insn_size,
			     bool batch)
{
	const unsigned opcode = code[0];
	if ((opcode & 0xfe) == 0xf6) {
		const unsigned form = opcode & 1;
		const unsigned width = form ? 4 : 1;
		if (size >= 2 + width && (code[1] & 0xf8) == 0xc0 &&
		    !X86_OUTPUT_UNSUPPORTED(handle, false)) {
			writeUnsignedRegisterImmediate(
				insn, &test32_rows[form],
				&test32_regs[form][code[1] & 7], code, 0,
				code[1], 2, width, insn_size);
			return true;
		}
	}
	if (opcode == 0x0f && size >= 4 && (code[1] & 0xf7) == 0xa4 &&
	    code[2] >= 0xc0 && !X86_OUTPUT_UNSUPPORTED(handle, false)) {
		++bare_opcode_hits[code[1]];
		writeDoubleShift32(code, insn, insn_size);
		return true;
	}
	return cs_decode_full_insn(handle, code, size, insn, insn_size, batch);
}
#endif
#endif
#endif
