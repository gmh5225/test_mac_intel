#include <capstone/capstone.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t mix(uint64_t h, const void *p, size_t n)
{
	const uint8_t *bytes = p;
	for (size_t i = 0; i < n; ++i)
		h = (h ^ bytes[i]) * UINT64_C(1099511628211);
	return h;
}

int main(int argc, char **argv)
{
	if (argc < 2)
		return 2;
	csh h;
	if (cs_open(CS_ARCH_XCORE, CS_MODE_LITTLE_ENDIAN, &h))
		return 3;
	cs_option(h, CS_OPT_DETAIL, strtoul(argv[1], NULL, 0));
	cs_insn *i = cs_malloc(h);
	if (!i || !i->detail)
		return 3;
	if (argc == 3) {
		FILE *f = fopen(argv[2], "rb");
		if (!f) return 2;
		uint8_t data[256]; size_t left = fread(data, 1, sizeof(data), f); fclose(f);
		const uint8_t *p = data; uint64_t ip = 0;
		while (left) {
			if (!cs_disasm_iter(h, &p, &left, &ip, i)) return 4;
			printf("%s %s\t", i->mnemonic, i->op_str);
			cs_xcore *x = &i->detail->xcore;
			for (uint8_t j = 0; j < x->op_count; ++j) {
				const cs_xcore_op *op = x->operands + j;
				if (op->type == XCORE_OP_REG) printf("R,%s;",cs_reg_name(h,op->reg));
				else if (op->type == XCORE_OP_IMM) printf("I,%d;",op->imm);
				else if (op->type == XCORE_OP_MEM) printf("M,%s,%s,%d,%d;",op->mem.base ? cs_reg_name(h,op->mem.base) : "",op->mem.index ? cs_reg_name(h,op->mem.index) : "",op->mem.disp,op->mem.direct);
				else return 5;
			}
			puts("");
		}
	} else {
		uint64_t counts[3] = {0}, text = 3, details = 7;
		for (unsigned word=0; word<65536; ++word) {
			for (unsigned tail=0; tail<7; ++tail) {
				uint32_t suffix=tail<3 ? (0x7fffu*tail) : (word*15991u+tail*46261u);
				unsigned n=tail < 4 ? tail : 4;
				uint8_t code[]={word,word>>8,suffix,suffix>>8};
				const uint8_t *p=code; size_t size=n; uint64_t ip=0x7fff1000+4u*word;
				if (!cs_disasm_iter(h,&p,&size,&ip,i)) {counts[0]++;continue;}
				if (p!=code+i->size || size!=n-i->size) return 6;
				counts[1]++;text=mix(mix(mix(text,&i->id,sizeof(i->id)),i->mnemonic,strlen(i->mnemonic)+1),i->op_str,strlen(i->op_str)+1);
				cs_xcore *x=&i->detail->xcore;
				if (x->op_count>sizeof(x->operands)/sizeof(*x->operands)) return 7;
				details=mix(details,&x->op_count,1);
				for(unsigned j=0;j<x->op_count;++j){
					const cs_xcore_op *op=x->operands+j;
					if(op->type!=XCORE_OP_REG && op->type!=XCORE_OP_MEM && op->type!=XCORE_OP_IMM) return 8;
					counts[2]+=op->type==XCORE_OP_MEM;
					details=mix(details,op,sizeof(*op));
				}
			}
		}
		printf("%" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",counts[0],counts[1],counts[2],text,details);
	}
	cs_free(i,1);
	cs_close(&h);
	return 0;
}
