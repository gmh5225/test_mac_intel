#include "arch/LoongArch/LoongArchInstPrinter.h"
#define GET_REGINFO_ENUM
#include "arch/LoongArch/LoongArchGenRegisterInfo.inc"

void observed_loong_name(MCInst *, SStream *, MCRegister);
extern const char *LoongArch_LLVM_getRegisterName(unsigned, unsigned);
int main(void)
{
	cs_struct handle = { 0 };
	MCInst mi = { 0 };
	mi.csh = &handle;
	unsigned checks = 0;
	for (unsigned r = 1; r < NUM_TARGET_REGS; ++r) {
		const char *name = LoongArch_LLVM_getRegisterName(r, LoongArch_RegAliasName);
		for (unsigned syntax = 0; syntax < 2; ++syntax) {
			handle.syntax = syntax ? CS_OPT_SYNTAX_NO_DOLLAR : CS_OPT_SYNTAX_DEFAULT;
			for (unsigned flags = 0; flags < 8; ++flags)
				for (unsigned left = 0; left < 10; ++left) {
					SStream a, b;
					memset(&a, 0x57, sizeof(a));
					SStream_Init(&a);
					memset(a.buffer, 0x57, sizeof(a.buffer));
					a.index = left == 9 ? 0 : SSTREAM_BUF_LEN - 1 - left;
					a.buffer[a.index] = '\0';
					a.markup_stream = !!(flags & 1);
					a.prefixed_by_markup = !!(flags & 2);
					a.is_closed = !!(flags & 4);
					memcpy(&b, &a, sizeof(b));
					observed_loong_name(&mi, &a, r);
					if (!syntax)
						SStream_concat1(&b, '$');
					SStream_concat0(&b, name);
					if (memcmp(&a, &b, sizeof(b))) {
						fprintf(stderr,"reg=%u left=%u flags=%u syntax=%u\n",r,left,flags,syntax);
						return 1;
					}
					++checks;
				}
		}
	}
	printf("%u\n",checks);
	return 0;
}
