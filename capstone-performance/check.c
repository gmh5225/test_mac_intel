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

#if defined(__unix__) || defined(__APPLE__)
#include <sys/mman.h>
#include <unistd.h>
/* Real page boundary after the last valid byte. Exercise every ModR/M/SIB,
 * both default address widths, the indexed group and an immediate tail. */
static void check_guarded_addresses(void)
{
    const size_t page = (size_t)sysconf(_SC_PAGESIZE);
    uint8_t *mapping = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANON, -1, 0);
    if (mapping == MAP_FAILED || mprotect(mapping + page, page, PROT_NONE))
        abort();
    const uint8_t opcodes[] = { 0x8b, 0x83, 0xff };
    uint8_t raw[15] = { 0x49 };
    for (unsigned op = 0; op < sizeof(opcodes); ++op) {
        for (unsigned m = 0; m < 256; ++m) {
            for (unsigned sib = 0; sib < 256; ++sib) {
                raw[1] = opcodes[op]; raw[2] = (uint8_t)m; raw[3] = (uint8_t)sib;
                size_t cut = 2 + (m + sib + op) % 10;
                uint8_t *end = mapping + page;
                memcpy(end - cut, raw, cut);
                check_legacy(end-cut, cut, 1, CS_MODE_64, false);
                check_legacy(end-cut+1, cut-1, 0, CS_MODE_32, false);
                /* For every SIB form at mod 0..2 exercise every truncated length. */
                if ((m & 7) == 4 && m < 0xc0 && ((m >> 3) & 7) == 0) {
                    for (size_t n = 2; n <= sizeof(raw); ++n) {
                        memcpy(end-n,raw,n);
                        check_legacy(end-n,n,1,CS_MODE_64,false);
                        check_legacy(end-n+1,n-1,0,CS_MODE_32,false);
                    }
                }
            }
        }
    }
    if (munmap(mapping, 2 * page)) abort();
}
#endif

static void check_vex_extent(const uint8_t *bytes, size_t length)
{
	X86ScanResult result = {0x55555555, 0xaaaaaaaa, 0xf00d, 0x5a};
	int status = tryVexTerminalScan(bytes, length, bytes[0], &result);
	record((uint32_t)status);
	record(result.opcode);
	record(result.opcode_pub);
	record(result.length);
	record(result.popcode_adjust);
	++states;
}

static void check_guarded_vex(void)
{
	const size_t page = (size_t)sysconf(_SC_PAGESIZE);
	uint8_t *mapping = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANON, -1, 0);
	if (mapping == MAP_FAILED || mprotect(mapping + page, page, PROT_NONE))
		abort();
	uint8_t *end = mapping + page;
	uint8_t raw[17] = {0};
	for (unsigned map = 0; map <= 32; ++map) {
		const bool two = map == 32;
		size_t head = two ? 3 : 4;
		raw[0] = two ? 0xc5 : 0xc4;
		for (unsigned op = 0; op < 256; ++op) {
			for (unsigned p = 0; p < 256; ++p) {
				if (!two) raw[1] = (uint8_t)(map | (op & 0xe0));
				raw[head - 2] = (uint8_t)p;
				raw[head - 1] = (uint8_t)op;
				raw[head] = (uint8_t)(op * 37 + p * 53);
				raw[head + 1] = (uint8_t)(op * 13 + p * 79);
				/* All maps including reserved maps, all W/L/pp/vvvv
				 * combinations, and every possible opcode. */
				for (size_t n = 1; n <= 15; ++n) {
					memcpy(end - n, raw, n);
					check_vex_extent(end - n, n);
				}
			}
		}
	}
	for (unsigned m = 0; m < 256; ++m)
		for (unsigned sib = 0; sib < 256; ++sib) {
			/* vaddps xmm, xmm, xmm/m128 includes register,
			 * SIB, RIP-relative and both displacement widths. */
			uint8_t vex[15] = {0xc5, 0xf0, 0x58, (uint8_t)m, (uint8_t)sib};
			for (size_t n = 1; n <= sizeof(vex); ++n) {
				memcpy(end-n, vex, n);
				check_vex_extent(end-n, n);
			}
		}
	if (munmap(mapping, 2 * page)) abort();
}

int test_terminal_states(void)
{
#if defined(__unix__) || defined(__APPLE__)
	check_guarded_addresses();
	check_guarded_vex();
#endif
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
