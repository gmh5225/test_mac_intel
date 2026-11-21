#include <capstone/capstone.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

int main(void)
{
#ifdef _WIN32
	if (_setmode(_fileno(stdout), _O_BINARY) == -1)
		return 2;
#endif
	unsigned states = 0, valid = 0;
	uint32_t rng = UINT32_C(0x1cb4a82d);
	const cs_mode modes[] = { CS_MODE_RISCV32, CS_MODE_RISCV64,
		(cs_mode)(CS_MODE_RISCV32 | CS_MODE_RISCV_C),
		(cs_mode)(CS_MODE_RISCV64 | CS_MODE_RISCV_C) };
	for (size_t m = 0; m < sizeof(modes) / sizeof(modes[0]); ++m) {
		csh h;
		if (cs_open(CS_ARCH_RISCV, modes[m], &h) != CS_ERR_OK ||
		    cs_option(h, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
			return 3;
		cs_insn *insn = cs_malloc(h);
		if (!insn || !insn->detail)
			return 4;
		cs_detail *detail = insn->detail;
		for (unsigned i = 0; i < 65536; ++i) {
			rng = rng * UINT32_C(1664525) + UINT32_C(1013904223);
			const uint32_t word = (rng & ~UINT32_C(0x7f)) | (i & 127);
			uint8_t bytes[4] = { (uint8_t)word, (uint8_t)(word >> 8),
				(uint8_t)(word >> 16), (uint8_t)(word >> 24) };
			size_t length = i & 0x100 ? 4 : (i >> 9) % 5;
			const uint8_t *cursor = bytes;
			uint64_t address = UINT64_C(0x100000) + i * 4u;
			memset(insn, (i >> 4) & 255, sizeof(*insn));
			memset(detail, (i >> 5) & 255, sizeof(*detail));
			insn->detail = detail;
			bool decoded = cs_disasm_iter(h, &cursor, &length, &address, insn);
			if (insn->detail != detail) return 5;
			const uint32_t header[] = { decoded, (uint32_t)cs_errno(h),
				(uint32_t)(cursor - bytes), (uint32_t)length, (uint32_t)address };
			if (fwrite(header, sizeof(header), 1, stdout) != 1 ||
			    fwrite(insn, offsetof(cs_insn, detail), 1, stdout) != 1 ||
			    fwrite(detail, offsetof(cs_detail, riscv) + sizeof(cs_riscv), 1, stdout) != 1)
				return 6;
			states++;
			valid += decoded;
		}
		cs_free(insn, 1);
		cs_close(&h);
	}
	fprintf(stderr, "%u states, %u decoded\n", states, valid);
	return valid == 0;
}
