#include "arch/WASM/WASMDisassembler.h"
#include "cs_priv.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

bool reference_instruction(csh, const uint8_t *, size_t, MCInst *, uint16_t *,
			   uint64_t, void *);
static uint64_t checked, accepted;
static csh handle;

static void check(const uint8_t *code, size_t len)
{
	for (int details = 0; details <= 1; ++details) {
		MCInst mi[2];
		cs_insn insn[2];
		cs_detail detail[2];
		uint16_t lengths[2] = { 0xabcd, 0xabcd };
		bool result[2];
		memset(mi, 0x59, sizeof(mi));
		memset(insn, 0x6d, sizeof(insn));
		memset(detail, 0xae, sizeof(detail));
		for (unsigned i = 0; i < 2; ++i) {
			mi[i].csh = (cs_struct *)(uintptr_t)handle;
			mi[i].flat_insn = &insn[i];
			insn[i].detail = details ? &detail[i] : NULL;
			result[i] = (i ? WASM_getInstruction : reference_instruction)(
				handle, code, len, &mi[i], &lengths[i],
				UINT64_C(0x10000000b), NULL);
			mi[i].flat_insn = NULL;
			insn[i].detail = NULL;
		}
		if (result[0] != result[1] || lengths[0] != lengths[1] ||
		    memcmp(&mi[0], &mi[1], sizeof(mi[0])) ||
		    memcmp(&insn[0], &insn[1], sizeof(insn[0])) ||
		    memcmp(&detail[0], &detail[1], sizeof(detail[0]))) {
			fprintf(stderr,"mismatch %" PRIu64 " len %zu detail %d\n",
				checked, len, details);
			exit(3);
		}
		if (result[1]) ++accepted;
		++checked;
	}
}

int main(void)
{
	if (cs_open(CS_ARCH_WASM, 0, &handle) != CS_ERR_OK) return 1;
	size_t page = (size_t)sysconf(_SC_PAGESIZE);
	uint8_t *p = mmap(NULL, 2*page, PROT_READ | PROT_WRITE,
			  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED || mprotect(p+page, page, PROT_NONE)) return 2;
	uint8_t *end = p+page;
	check(end, 0);
	uint32_t rand_state = 0x6d225a9b;
	for (int op = 0x28; op <= 0x3e; ++op) {
		end[-1] = op;
		check(end - 1, 1);
		end[-2] = op;
		for (int a = 0; a < 256; ++a) {
			end[-1] = a;
			check(end - 2, 2);
		}
		end[-3] = op;
		for (int a = 0; a < 256; ++a) {
			end[-2] = a;
			for (int b = 0; b < 256; ++b) {
				end[-1] = b;
				check(end - 3, 3);
			}
		}
		for (int n = 4; n <= 13; ++n) {
			uint8_t *code = end-n;
			code[0] = op;
			for (int i = 0; i < 4096; ++i) {
				for (int j = 1; j < n; ++j) {
					rand_state = rand_state * 1664525u + 1013904223u;
					code[j] = (uint8_t)(rand_state >> 24);
				}
				check(code, n);
			}
		}
	}
	printf("%" PRIu64 " %" PRIu64 "\n", checked, accepted);
	munmap(p, page*2);
	cs_close(&handle);
	return 0;
}
