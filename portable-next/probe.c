#include "arch/X86/X86ScanAdapter.h"
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

static void field_diff(const char *name, const void *a, const void *b, size_t n)
{
	const unsigned char *x = a, *y = b;
	for (size_t i = 0; i < n; ++i)
		if (x[i] != y[i])
			printf(" %s+%zu=%02x/%02x", name, i, x[i], y[i]);
}

int main(void)
{
	const unsigned values[] = { 0, 1, 9, 10, 0x7f, 0x80, 0xff, 0x80000000, 0xffffffff };
	const unsigned ops[] = { 0x80, 0x81, 0x83 };
	printf("pointer=%zu detail_x86=%zu ops=%zu stride=%zu opimm=%zu opsize=%zu\n",
	       sizeof(void *), offsetof(cs_detail, x86), offsetof(cs_x86, operands), sizeof(cs_x86_op),
	       offsetof(cs_x86_op, imm), offsetof(cs_x86_op, size));
	unsigned records = 0, different = 0;
	for (unsigned bits = 32; bits <= 64; bits += 32) {
		for (unsigned detail_on = 0; detail_on <= 1; ++detail_on) {
			csh handles[2] = { 0 };
			cs_opt_mnem custom = { X86_INS_UD2, "ud2" };
			for (unsigned i=0; i<2; ++i)
				if (cs_open(CS_ARCH_X86, bits==64 ? CS_MODE_64 : CS_MODE_32, &handles[i]) ||
				    cs_option(handles[i], CS_OPT_DETAIL, detail_on ? CS_OPT_ON : CS_OPT_OFF)) return 2;
			if (cs_option(handles[1], CS_OPT_MNEMONIC, (size_t)&custom)) return 3;
			for (unsigned rex=0; rex<3; ++rex) for (unsigned o=0; o<3; ++o)
				for (unsigned v=0; v<sizeof(values)/sizeof(values[0]); ++v) {
					uint8_t bytes[16] = { 0 };
					unsigned n=0;
					if (rex) bytes[n++] = rex==1 ? 0x41 : 0x49;
					bytes[n++]=(uint8_t)ops[o]; bytes[n++]=0x7d; bytes[n++]=0x70;
					unsigned width=ops[o]==0x81 ? 4 : 1;
					for (unsigned i=0;i<width;++i)bytes[n++]=(uint8_t)(values[v]>>(8*i));
					cs_insn ins[2]; cs_detail det[2];bool ok[2];uint64_t ip[2];size_t left[2];const uint8_t *p[2];
					for(unsigned i=0;i<2;++i) {
						memset(&ins[i],6,sizeof(ins[i]));memset(&det[i],6,sizeof(det[i]));
						ins[i].is_alias=ins[i].usesAliasDetails=ins[i].illegal=false;ins[i].detail=detail_on?&det[i]:NULL;
						ip[i]=UINT64_MAX-6;p[i]=bytes;left[i]=n;
						ok[i]=i ? cs_disasm_iter(handles[i], &p[i], &left[i], &ip[i], &ins[i]) :
							(bits==64 ? X86_disasmIterText : X86_disasmIter32)(handles[i], &p[i], &left[i], &ip[i], &ins[i]);
						ins[i].detail=NULL;
					}
					++records;
					if(!ok[0] || !ok[1] || p[0]!=p[1] || left[0]!=left[1] || ip[0]!=ip[1])return 4;
					const bool mismatch=memcmp(&ins[0],&ins[1],sizeof(cs_insn)) || memcmp(&det[0],&det[1],sizeof(cs_detail));
					different+=mismatch;
					printf("%u %u %u %02x %08x %u |%s %s|%s %s|",bits,detail_on,rex,ops[o],values[v],(unsigned)mismatch,
					       ins[0].mnemonic,ins[0].op_str,ins[1].mnemonic,ins[1].op_str);
					if(detail_on)printf(" imm=%" PRId64 "/%" PRId64 " sz=%u/%u",
							det[0].x86.operands[1].imm,det[1].x86.operands[1].imm,
							det[0].x86.operands[1].size,det[1].x86.operands[1].size);
					if(mismatch){field_diff("record",&ins[0],&ins[1],sizeof(cs_insn));field_diff("detail",&det[0],&det[1],sizeof(cs_detail));}
					putchar('\n');
				}
			cs_close(&handles[1]);cs_close(&handles[0]);
		}
	}
	printf("tested %u differences %u\n",records,different);
	return 0;
}
