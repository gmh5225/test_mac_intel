/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include "../../cs_disasm_internal.h"

#ifdef CAPSTONE_X86_PUBLIC_OUTPUT
#if defined(__ELF__) && defined(__clang__)
#pragma clang section text = ".cs_x86_public_output_text"
#endif
CS_PRESERVE_MOST bool X86_decodePublicRecord(cs_struct *handle,
					    const uint8_t *code, size_t size,
					    cs_insn *insn, uint16_t *length,
					    bool batch)
{
	/* The outer iterator owns detail visibility, skipdata and cursor updates.
	 * Its fixed text path only needs the decoded record and its length. */
	if (!batch && !handle->skipdata && !handle->no_text) {
		if (handle->mode == CS_MODE_32)
			return X86_decodeFixedRecord32(handle, code, size, insn,
						       length);
		if (handle->mode == CS_MODE_64)
			return X86_decodeFixedRecord64(handle, code, size, insn,
						       length);
	}
	return cs_decode_full_insn(handle, code, size, insn, length, batch);
}
#endif
