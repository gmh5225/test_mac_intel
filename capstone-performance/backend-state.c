#include <capstone/capstone.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static uint64_t hash = UINT64_C(0xcbf29ce484222325);
static unsigned long calls, valid;
static void digest(const void *data, size_t n)
{
	const unsigned char *p = data;
	for (size_t i = 0; i < n; ++i)
		hash = (hash ^ p[i]) * UINT64_C(1099511628211);
}
static void visit(csh h, const uint8_t *code, size_t len, bool want_detail)
{
	cs_insn out;
	cs_detail detail;
	memset(&out, 0xa5, sizeof(out));
	memset(&detail, 0x5a, sizeof(detail));
	out.detail = want_detail ? &detail : NULL;
	uint64_t address = UINT64_MAX - 12;
	const uint8_t *cursor = code;
	size_t left = len;
	bool r = cs_disasm_iter(h, &cursor, &left, &address, &out);
	ptrdiff_t consumed = cursor - code;
	digest(&r, sizeof(r));
	digest(&address, sizeof(address));
	digest(&left, sizeof(left));
	digest(&consumed, sizeof(consumed));
	digest(&out, offsetof(cs_insn, detail));
	if (want_detail)
		digest(&detail, offsetof(cs_detail, x86) + sizeof(cs_x86));
	++calls;
	valid += r;
}
int main(void)
{
	size_t page = (size_t)sysconf(_SC_PAGESIZE);
	unsigned char *mem = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE,
				  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mem == MAP_FAILED || mprotect(mem + page, page, PROT_NONE))
		return 2;
	static const uint8_t prefixes[][6] = {
		{}, {0x48}, {0x0f}, {0x66,0x0f}, {0x67}, {0xf2,0x0f},
		{0x0f,0x38}, {0x66,0x0f,0x3a}, {0xc5,0xf8}, {0xc4,0xe2,0x79},
		{0x62,0xf1,0x7c,0x48}, {0x62,0xf2,0x7d,0x89},
		{0xd5,0x88}, {0xf0}, {0x66,0x48}, {0x8f,0xe9,0x78},
	};
	static const uint8_t plen[] = {0,1,1,2,1,2,2,3,2,3,4,4,2,1,2,3};
	static const cs_mode modes[] = { CS_MODE_16, CS_MODE_32, CS_MODE_64 };
	static const size_t syntax[] = { CS_OPT_SYNTAX_INTEL, CS_OPT_SYNTAX_ATT,
					CS_OPT_SYNTAX_MASM };
	for (unsigned mode = 0; mode < 3; ++mode) {
		csh h;
		if (cs_open(CS_ARCH_X86, modes[mode], &h)) return 3;
		for (unsigned d = 0; d <= 1; ++d) {
			if (cs_option(h, CS_OPT_DETAIL, d ? CS_OPT_ON : CS_OPT_OFF)) return 4;
			for (unsigned p = 0; p < sizeof(plen); ++p) {
				if (cs_option(h, CS_OPT_SYNTAX, syntax[(mode+p+d)%3])) return 5;
				for (unsigned op = 0; op < 256; ++op) {
					for (unsigned mr = 0; mr < 256; mr += 4) {
						uint8_t b[16] = {0};
						memcpy(b, prefixes[p], plen[p]);
						b[plen[p]] = op;
						b[plen[p]+1] = mr + ((mode+p+op)&3);
						for (size_t k = plen[p]+2; k < sizeof(b); ++k)
							b[k] = (uint8_t)(mr*17+op*101+k*29);
						size_t len = (mr & 8) ? 15 : (op + mr + mode) % 16;
						uint8_t *q = mem + page - len;
						memcpy(q, b, len);
						visit(h, q, len, d);
					}
				}
			}
		}
		if (cs_close(&h)) return 6;
	}
	printf("%lu states, %lu decoded, %016" PRIx64 "\n", calls, valid, hash);
	return munmap(mem, 2*page) != 0;
}
