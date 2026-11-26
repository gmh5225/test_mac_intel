#include "arch/WASM/WASMInstPrinter.h"
#include "arch/WASM/WASMMapping.h"
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

void wasm_reference(MCInst *, SStream *, void *);
static uint32_t format_hash;
static unsigned calls, behavior;
static cs_vsnprintf_t original_hook;

static int traced(char *dst, size_t cap, const char *fmt, va_list ap)
{
	++calls;
	if (behavior==4) cs_vsnprintf=original_hook;
	for (const unsigned char *s = (const unsigned char *)fmt; *s; ++s)
		format_hash = format_hash * 16777619u ^ *s;
	int ret = vsnprintf(dst, cap, fmt, ap);
	if (behavior == 2) return -1;
	if (behavior == 3 && ret >= 2) return 2;
	return ret;
}

int main(void)
{
	MCInst mi = {0};
	const cs_vsnprintf_t saved = cs_vsnprintf;
	original_hook=saved;
	const uint32_t values[]={0,1,9,10,15,16,127,128,255,256,4095,4096,65535,65536,0x12345678,0x80000000,0xffffffff};
	const size_t indices[] = {0, 1, 7, SSTREAM_BUF_LEN - 24, SSTREAM_BUF_LEN - 5, SSTREAM_BUF_LEN - 2, SSTREAM_BUF_LEN - 1, SSTREAM_BUF_LEN, SSTREAM_BUF_LEN + 8};
	const wasm_op_type types[] = {WASM_OP_NONE, WASM_OP_VARUINT32, WASM_OP_VARUINT64, WASM_OP_UINT32, WASM_OP_UINT64, WASM_OP_IMM, WASM_OP_INT7, WASM_OP_BRTABLE};
	unsigned long checks = 0;
	for (unsigned id=0; id<256; ++id) {
		if (id!=0x20 && id!=0x28 && id!=0x36) continue;
		mi.Opcode = id;
		for (unsigned t=0; t<sizeof(types)/sizeof(*types); ++t) {
			memset(&mi.wasm_data, 0xb7, sizeof(mi.wasm_data));
			mi.wasm_data.type=types[t];
			if (types[t]==WASM_OP_BRTABLE) mi.wasm_data.brtable.address=UINT32_C(0xfedcba98);
			if (types[t]!=WASM_OP_IMM && types[t]!=WASM_OP_VARUINT32) continue;
            for (unsigned left=0;left<sizeof(values)/sizeof(*values);++left)
                for (unsigned right=0;right<(types[t]==WASM_OP_IMM?sizeof(values)/sizeof(*values):1);++right) {
                    if(types[t]==WASM_OP_IMM){mi.wasm_data.immediate[0]=values[left];mi.wasm_data.immediate[1]=values[right];}
                    else mi.wasm_data.varuint32=values[left];
            for (unsigned k=0; k<sizeof(indices)/sizeof(*indices); ++k)
				for (unsigned flags=0; flags<16; ++flags)
					for (behavior=0; behavior<5; ++behavior) {
						SStream ref, test;
						memset(&ref, 0x5e, sizeof(ref));
						ref.index=indices[k];
						ref.is_closed=flags&1;
						ref.markup_stream=(flags&2)!=0;
						ref.prefixed_by_markup=(flags&4)!=0;
						ref.unsigned_num=(flags&8)!=0;
						memcpy(&test,&ref,sizeof(ref));
						cs_vsnprintf=behavior?traced:saved;
						calls=format_hash=0;
						wasm_reference(&mi,&ref,NULL);
						unsigned want_calls=calls, want_hash=format_hash;
						cs_vsnprintf=behavior?traced:saved;
						calls=format_hash=0;
						WASM_printInst(&mi,&test,NULL);
						if (memcmp(&ref,&test,sizeof(ref)) || calls!=want_calls || format_hash!=want_hash) {
							fprintf(stderr,"opcode=%u type=%u index=%zu flags=%u hook=%u\n",id,t,indices[k],flags,behavior);
							return 2;
						}
						++checks;
					}
					}
		}
	}
	cs_vsnprintf=saved;
	printf("%lu\n",checks);
	return checks>0 ? 0 : 1;
}
