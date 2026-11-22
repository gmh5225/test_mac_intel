#include "MCInst.h"
#include "SStream.h"
#include <ctype.h>
#include <stdio.h>
#include <string.h>

void printFormattedRegName(const MCAsmInfo *info, MCRegister reg, SStream *out);
const char *SystemZ_LLVM_getRegisterName(unsigned reg);

static void reference(MCAsmInfo *info, const char *name, SStream *out)
{
	if (info->assemblerDialect == SYSTEMZASMDIALECT_AD_HLASM) {
		SStream_concat0(markup_OS(out, Markup_Register), name + 1);
	} else {
		SStream_concat1(markup_OS(out, Markup_Register), '%');
		SStream_concat0(markup_OS(out, Markup_Register), name);
	}
}

int main(void)
{
	const size_t positions[] = { 0, 5, 496, 503, 506, 507, 508, 509, 510, 511 };
	unsigned comparisons = 0;
	for (unsigned reg = 1; reg <= 194; ++reg) {
		const char *name = SystemZ_LLVM_getRegisterName(reg);
		if (!name || !*name) return 2;
		for (unsigned dialect = 0; dialect < 2; ++dialect) {
			MCAsmInfo info = {0};
			info.assemblerDialect = dialect ? SYSTEMZASMDIALECT_AD_HLASM : SYSTEMZASMDIALECT_AD_ATT;
			if (dialect && (!isalpha((unsigned char)name[0]) || !isdigit((unsigned char)name[1]))) continue;
			for (unsigned flags = 0; flags < 8; ++flags)
				for (unsigned n = 0; n < sizeof(positions)/sizeof(positions[0]); ++n) {
					SStream expected,actual;
					memset(&expected, 0xa5, sizeof(expected));expected.index=positions[n];expected.buffer[positions[n]]=0;
					expected.is_closed=(flags&1)!=0;expected.markup_stream=(flags&2)!=0;expected.prefixed_by_markup=(flags&4)!=0;expected.unsigned_num=false;
					memcpy(&actual,&expected,sizeof(actual));reference(&info,name,&expected);printFormattedRegName(&info,reg,&actual);
					if (memcmp(&expected,&actual,sizeof(actual))) {
						fprintf(stderr,"register %u dialect %u stream flags %u position %zu\n",reg,dialect,flags,positions[n]);return 3;
					}
					++comparisons;
				}
		}
	}
	printf("%u\n",comparisons);
	return comparisons > 20000 ? 0 : 4;
}
