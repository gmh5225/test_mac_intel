#include <capstone/capstone.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif
#include "cs_priv.h"
#include "arch/X86/X86Mapping.h"
#define GET_INSTRINFO_ENUM
#ifdef CAPSTONE_X86_REDUCE
#include "arch/X86/X86GenInstrInfo_reduce.inc"
#else
#include "arch/X86/X86GenInstrInfo.inc"
#endif
int main(void)
{
#ifdef _WIN32
	if (_setmode(_fileno(stdout), _O_BINARY) < 0) return 2;
#endif
	csh handle;
	if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle)) return 3;
	uint32_t count = X86_INSTRUCTION_LIST_END;
	if (fwrite(&count, sizeof(count), 1, stdout) != 1) return 4;
	for (unsigned cached = 0; cached < 2; ++cached) {
		cs_struct *h = cached ? (cs_struct *)(uintptr_t)handle : NULL;
		for (unsigned n = 0; n < count + 4; ++n) {
			unsigned id = n == count+3 ? UINT32_MAX : n == count+2 ? UINT16_MAX : n;
			uint64_t flags = UINT64_C(0xbad0bad000000003);
			const uint8_t *a = X86_get_op_access(h, id, &flags);
			uint8_t out[7] = { a != NULL };
			if (a) {
				for (unsigned i=0; i < 6; ++i) {
					out[1+i] = a[i];
					if (!a[i]) break;
				}
			}
			if (fwrite(&flags,sizeof(flags),1,stdout)!=1 || fwrite(out,1,sizeof(out),stdout)!=sizeof(out)) return 4;
		}
	}
	return cs_close(&handle) != CS_ERR_OK;
}
