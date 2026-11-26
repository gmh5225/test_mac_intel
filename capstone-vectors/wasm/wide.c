#include <capstone/capstone.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned encode(uint64_t v, uint8_t *out)
{
	unsigned length = 0;
	do {
		uint8_t byte = v & 127;
		v >>= 7;
		if (!v && !(byte & 64)) {
			out[length++] = byte;
			break;
		}
		out[length++] = byte | 128;
	} while (length != 10);
	return length;
}

int main(void)
{
	const uint64_t starts[] = {0, 0xfffffffd, 0xfffffffe, 0xffffffff, UINT64_C(0x100000000), UINT64_C(0x76543210abcdef00), UINT64_MAX-2, UINT64_MAX};
	const uint64_t values[] = {0, 63, 64, 127, 128, 0x7fffffff, 0xffffffff, UINT64_C(0x100000000), UINT64_C(0x100000001), UINT64_C(0x10304050607080), INT64_MAX};
	const cs_opt_mem mem = {malloc, calloc, realloc, free, vsnprintf};
	if (cs_option(0, CS_OPT_MEM, (uintptr_t)&mem) != CS_ERR_OK) return 1;
	const bool diet = cs_support(CS_SUPPORT_DIET);
	unsigned checked=0, bad_number=0, bad_table=0;
	for (unsigned detail=0; detail != 2; ++detail) {
		csh h;
		if (cs_open(CS_ARCH_WASM,0,&h) || cs_option(h,CS_OPT_DETAIL,detail ? CS_OPT_ON : CS_OPT_OFF))
			return 1;
		for (unsigned i=0; i<sizeof(values)/sizeof(*values); ++i) {
			uint8_t bytes[20]={0x42};
			unsigned n=1+encode(values[i],bytes+1);
			memcpy(bytes+n, "\x0e\x02\x01\x00\x03", 5);
			for (unsigned j=0; j<sizeof(starts)/sizeof(*starts); ++j) {
				for (unsigned iter=0; iter!=2; ++iter) {
					const uint8_t *ptr=bytes;
					size_t left=n+5;
					uint64_t ip=starts[j];
					cs_insn *out=iter ? cs_malloc(h) : NULL;
					const size_t count=iter ? 1 : cs_disasm(h,bytes,left,ip,0,&out);
					if ((iter && !out) || (!iter && count!=2)) return 2;
					for (unsigned step=0; step!=2; ++step) {
						if (iter && !cs_disasm_iter(h,&ptr,&left,&ip,out)) return 3;
						const cs_insn *v=iter ? out : &out[step];
						const uint64_t target=starts[j]+n+2;
						char text[96];
						if (!step) {
							snprintf(text,sizeof(text),"0x%" PRIx64,values[i]);
							if (v->id!=WASM_INS_I64_CONST || v->size!=n || v->address!=starts[j]) return 4;
							if (detail && (!v->detail || v->detail->wasm.op_count!=1 || v->detail->wasm.operands[0].varuint64!=values[i])) return 5;
							bad_number += !diet && strcmp(text,v->op_str)!=0;
						} else {
							snprintf(text,sizeof(text),"0x2, [0x%" PRIx64 "], 0x3",target);
							if (v->id!=WASM_INS_BR_TABLE || v->size!=5 || v->address!=starts[j]+n) return 6;
							if (detail && (!v->detail || v->detail->wasm.op_count!=1 || v->detail->wasm.operands[0].brtable.address!=target || v->detail->wasm.operands[0].brtable.default_target!=3)) return 7;
							bad_table += !diet && strcmp(text,v->op_str)!=0;
						}
						++checked;
					}
					if (iter && (left || ptr!=bytes+n+5 || ip!=starts[j]+n+5)) return 8;
					cs_free(out,count);
				}
			}
		}
		cs_close(&h);
	}
	printf("%u %u %u\n",checked,bad_number,bad_table);
	return 0;
}
