#include <capstone/capstone.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
	unsigned cases = 0, documented = 0, reserved = 0;
	for (unsigned mode = 0; mode < 2; ++mode) {
		csh handle;
		if (cs_open(CS_ARCH_X86, mode ? CS_MODE_64 : CS_MODE_32, &handle) ||
		    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON))
			return 2;
		cs_insn *insn = cs_malloc(handle);
		if (!insn)
			return 3;
		for (unsigned prefix = 0; prefix <= (mode ? 16u : 0u); ++prefix) {
			for (unsigned mr = 0xc0; mr <= 0xff; ++mr) {
				uint8_t bytes[7] = {0x66};
				unsigned size = 1;
				if (prefix)
					bytes[size++] = (uint8_t)(0x40 + prefix - 1);
				bytes[size++] = 0x0f;
				bytes[size++] = 0x78;
				bytes[size++] = (uint8_t)mr;
				bytes[size++] = 8;
				bytes[size++] = 4;
				for (unsigned n = 0; n <= size; ++n) {
					const uint8_t *code = bytes;
					size_t left = n;
					uint64_t address = 0x1000;
					bool ok = cs_disasm_iter(handle, &code, &left, &address, insn);
					++cases;
					if (!ok) {
						if (code != bytes || left != n || address != 0x1000 || (n == size && !(mr & 0x38)))
							return 4;
						continue;
					}
					if (n != size || left || address != 0x1000 + n || code != bytes + size ||
					    insn->id != X86_INS_EXTRQ || insn->size != n || memcmp(insn->bytes, bytes, n))
						return 5;
					if (mr & 0x38)
						++reserved;
					else
						++documented;
				}
			}
		}
		cs_free(insn, 1);
		cs_close(&handle);
	}
	printf("%u %u %u\n", cases, documented, reserved);
	return 0;
}
