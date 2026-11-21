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
	const cs_mode modes[] = {
		CS_MODE_32, CS_MODE_64,
		(cs_mode)(CS_MODE_32 | CS_MODE_BIG_ENDIAN),
		(cs_mode)(CS_MODE_64 | CS_MODE_BIG_ENDIAN),
		(cs_mode)(CS_MODE_64 | CS_MODE_PWR7),
		(cs_mode)(CS_MODE_64 | CS_MODE_PWR8),
		(cs_mode)(CS_MODE_64 | CS_MODE_PWR9),
		(cs_mode)(CS_MODE_64 | CS_MODE_PWR10),
		(cs_mode)(CS_MODE_64 | CS_MODE_PPC_ISA_FUTURE),
		(cs_mode)(CS_MODE_64 | CS_MODE_PWR10 | CS_MODE_BIG_ENDIAN),
		(cs_mode)(CS_MODE_32 | CS_MODE_SPE | CS_MODE_BIG_ENDIAN),
		(cs_mode)(CS_MODE_32 | CS_MODE_PS | CS_MODE_BIG_ENDIAN),
		(cs_mode)(CS_MODE_64 | CS_MODE_QPX | CS_MODE_BIG_ENDIAN),
		(cs_mode)(CS_MODE_64 | CS_MODE_SPE | CS_MODE_QPX | CS_MODE_PS),
		(cs_mode)(CS_MODE_32 | CS_MODE_SPE | CS_MODE_PS | CS_MODE_BIG_ENDIAN),
		(cs_mode)(CS_MODE_32 | CS_MODE_BOOKE),
	};
	for (size_t m = 0; m < sizeof(modes) / sizeof(modes[0]); ++m) {
		csh h;
		if (cs_open(CS_ARCH_PPC, modes[m], &h) != CS_ERR_OK ||
		    cs_option(h, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
			return 3;
		cs_insn *insn = cs_malloc(h);
		if (!insn || !insn->detail)
			return 4;
		cs_detail *detail = insn->detail;
		for (unsigned i = 0; i < 16384; ++i) {
			rng = rng * UINT32_C(1664525) + UINT32_C(1013904223);
			uint32_t first = (rng & UINT32_C(0x03ffffff)) | ((uint32_t)(i & 63) << 26);
			uint32_t second = rng * UINT32_C(69069) + 1;
			/* Include valid power10 pld and plxsd forms, as well as malformed pairs. */
			if ((i & 127) == 1) {
				first = UINT32_C(0x04020000);
				second = (i & 128) ? UINT32_C(0xe4230000) : UINT32_C(0xa8230000);
			}
			uint8_t bytes[8];
			for (unsigned j = 0; j < 4; ++j) {
				const unsigned shift = (modes[m] & CS_MODE_BIG_ENDIAN ? 3 - j : j) * 8;
				bytes[j] = (uint8_t)(first >> shift);
				bytes[j+4] = (uint8_t)(second >> shift);
			}
			size_t length = i & 0x100 ? 8 : (i >> 2) % 9;
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
			    fwrite(detail, sizeof(*detail), 1, stdout) != 1)
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
