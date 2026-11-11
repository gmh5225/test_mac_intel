#include <inttypes.h>
#include <stdio.h>

static uint64_t digest = UINT64_C(14695981039346656037);
static uint64_t states;
static void record(uint32_t v)
{
	digest = (digest ^ v) * UINT64_C(1099511628211);
}

static void check_legacy(const uint8_t *bytes, size_t size, size_t offset,
			 cs_mode mode, bool indexed)
{
	for (unsigned flags = 0; flags < 4; ++flags) {
		unsigned id = UINT32_C(0xa5a55a5a);
		uint16_t length = UINT16_C(0xbeef);
		int status;
		if (indexed)
			status = tryLegacyPrefixedScan(bytes, size, mode, &id, &length,
						       flags & 1, true, flags & 2);
		else
			status = trySimpleLegacyScan(bytes, size, mode, bytes[offset],
						     offset, &id, &length,
						     flags & 1, flags & 2);
		record((uint32_t)status);
		record(id);
		record(length);
		++states;
	}
}

int test_terminal_states(void)
{
	static const cs_mode modes[] = {
		CS_MODE_16, CS_MODE_32, CS_MODE_64,
		CS_MODE_16 | CS_MODE_32, CS_MODE_32 | CS_MODE_64
	};
	static const uint8_t prefix[] = {0, 0x40, 0x48, 0x4f, 0x66, 0x67, 0x64, 0x0f};
	uint32_t random = 0x243f6a88;
	uint8_t bytes[20];
	for (unsigned op = 0; op < 256; ++op) {
		for (unsigned modrm = 0; modrm < 256; ++modrm) {
			for (unsigned j = 0; j < sizeof(bytes); ++j) {
				random = random * UINT32_C(1664525) + UINT32_C(1013904223);
				bytes[j] = (uint8_t)(random >> 24);
			}
			for (unsigned k = 0; k < sizeof(prefix); ++k) {
				size_t off = k != 0;
				bytes[0] = prefix[k];
				bytes[off] = (uint8_t)op;
				bytes[off+1] = (uint8_t)modrm;
				for (unsigned m = 0; m < sizeof(modes)/sizeof(modes[0]); ++m) {
					/* Include every addressing byte in 16-bit and long mode,
					 * plus every truncation point and the architectural limit. */
					size_t cut = 1 + (size_t)((op + 5 * modrm + k + m) % 17);
					if (cut > off)
						check_legacy(bytes, cut, off, modes[m], false);
					if (off)
						check_legacy(bytes, cut, off, modes[m], true);
				}
			}
			for (unsigned form = 0; form < 2; ++form) {
				bytes[0] = form ? 0xc4 : 0xc5;
				bytes[1] = (uint8_t)op;
				bytes[2] = (uint8_t)modrm;
				for (unsigned n = 1; n <= 17; ++n) {
					X86ScanResult result = {0x55555555, 0xaaaaaaaa, 0xf00d, 0x5a};
					int s = tryVexTerminalScan(bytes, n, bytes[0], &result);
					record((uint32_t)s);
					record(result.opcode);
					record(result.opcode_pub);
					record(result.length);
					record(result.popcode_adjust);
					++states;
				}
			}
		}
	}
	printf("states=%" PRIu64 " digest=%016" PRIx64 "\n", states, digest);
	return 0;
}
