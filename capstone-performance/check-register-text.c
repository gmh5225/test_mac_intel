#include "arch/X86/X86Disassembler.h"
#include "arch/X86/X86InstPrinter.h"
#include "arch/X86/X86Mapping.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	csh h;
	cs_err (*open)(cs_arch, cs_mode, csh *);
	cs_err (*option)(csh, cs_opt_type, size_t);
	bool (*next)(csh, const uint8_t **, size_t *, uint64_t *, cs_insn *);
	cs_err (*close)(csh *);
} api;

static bool compare(api *base, api *newer, const uint8_t *code, size_t length,
		    unsigned seed, bool alias)
{
	cs_insn output[2];
	api *versions[] = { base, newer };
	size_t left[2] = { length, length };
	uint64_t ip[2] = { 0x140123456, 0x140123456 };
	bool ok[2];
	size_t used[2];
	for (unsigned i = 0; i < 2; ++i) {
		cs_insn *insn = &output[i];
		memset(insn, seed, sizeof(*insn));
		insn->detail = NULL;
		const uint8_t *start = code;
		if (alias) {
			memcpy(insn->op_str, code, length);
			start = (const uint8_t *)insn->op_str;
		}
		const uint8_t *cursor = start;
		ok[i] = versions[i]->next(versions[i]->h, &cursor, &left[i], &ip[i], insn);
		used[i] = (size_t)(cursor - start);
	}
	return ok[0] == ok[1] && used[0] == used[1] && left[0] == left[1] &&
	       ip[0] == ip[1] && !memcmp(output, output + 1, sizeof(output[0]));
}

static bool admit(csh handle, const uint8_t code[2])
{
	cs_struct *h = (cs_struct *)(uintptr_t)handle;
	cs_insn out = { 0 };
	MCInst mi;
	MCInst_InitX86(&mi);
	mi.csh = h;
	mi.flat_insn = &out;
	if (!X86_getInstruction(handle, code, 2, &mi, &out.size, 0, h->getinsn_info))
		return false;
	X86_get_insn_id(h, &out, mi.Opcode);
	return X86_Intel_printPublicRegisterPair(&mi, code);
}

static int coverage(const char *file, unsigned bits)
{
	FILE *input = fopen(file, "rb");
	if (!input || fseek(input, 0, SEEK_END)) return 9;
	long end = ftell(input);
	if (end <= 0 || fseek(input, 0, SEEK_SET)) return 9;
	size_t bytes = (size_t)end;
	uint8_t *data = malloc(bytes);
	if (!data || fread(data, 1, bytes, input) != bytes) return 9;
	fclose(input);
	csh handle;
	if (cs_open(CS_ARCH_X86, bits == 64 ? CS_MODE_64 : CS_MODE_32, &handle)) return 9;
	cs_struct *h = (cs_struct *)(uintptr_t)handle;
	unsigned long long admitted=0, decoded=0, rejected=0;
	for (size_t pos=0; pos<bytes;) {
		MCInst mi;
		MCInst_InitX86(&mi);
		cs_insn insn={0};
		mi.flat_insn=&insn;
		mi.csh=h;
		mi.address=insn.address=0x140000000ULL+pos;
		uint16_t size=0;
		if (!X86_getInstruction(handle,data+pos,bytes-pos,&mi,&size,mi.address,h->getinsn_info)) {
			++rejected; ++pos; continue;
		}
		if (!size || size>bytes-pos) return 10;
		++decoded;
		insn.size=size;
		X86_get_insn_id(h,&insn,mi.Opcode);
		if (insn.id!=X86_INS_VPCMP && X86_Intel_printPublicRegisterPair(&mi,data+pos)) ++admitted;
		pos+=size;
	}
	printf("decoded=%llu rejected=%llu direct_register_pairs=%llu\n",decoded,rejected,admitted);
	free(data);
	cs_close(&handle);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc == 3) return coverage(argv[1], (unsigned)atoi(argv[2]));
	if (argc != 2)
		return 2;
	void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
	if (!library)
		return 3;
	api base = { 0 }, newer = {0, cs_open, cs_option, cs_disasm_iter, cs_close};
	*(void **)(&base.open) = dlsym(library, "cs_open");
	*(void **)(&base.option) = dlsym(library, "cs_option");
	*(void **)(&base.next) = dlsym(library, "cs_disasm_iter");
	*(void **)(&base.close) = dlsym(library, "cs_close");
	if (!base.open || !base.option || !base.next || !base.close)
		return 4;
	const cs_mode modes[] = {CS_MODE_16, CS_MODE_32, CS_MODE_64};
	const cs_opt_value syntaxes[] = {CS_OPT_SYNTAX_INTEL, CS_OPT_SYNTAX_MASM, CS_OPT_SYNTAX_ATT};
	const uint8_t prefixes[][3] = {{0}, {0x66}, {0x48}, {0x4f}, {0xf3},
		{0x3e}, {0x0f}, {0x66,0x0f}, {0xf3,0x0f}, {0xc5,0xf8}, {0xc4,0xe1,0x79}};
	const uint8_t lens[] = {0,1,1,1,1,1,1,2,2,2,3};
	unsigned checks=0;
	for (unsigned m=0;m<3;++m) {
		if (base.open(CS_ARCH_X86,modes[m],&base.h) || newer.open(CS_ARCH_X86,modes[m],&newer.h))
			return 5;
		const uint8_t rr[]={0x89,0xc8}, mem[]={0x89,0x08};
		if (!admit(newer.h,rr) || admit(newer.h,mem))
			return 6;
		for (unsigned syntax=0;syntax<3;++syntax) {
			if (base.option(base.h,CS_OPT_SYNTAX,syntaxes[syntax]) || newer.option(newer.h,CS_OPT_SYNTAX,syntaxes[syntax]))
				return 7;
			for (unsigned p=0;p<sizeof(lens);++p) {
				for (unsigned op=0;op<256;++op)for (unsigned rm=0xc0;rm<=0xff;++rm) {
					uint8_t code[15]={0};
					memcpy(code,prefixes[p],lens[p]);code[lens[p]]=op;code[lens[p]+1]=rm;
					size_t length=(op+rm)%7==0 ? lens[p]+1 : sizeof(code);
					if (!compare(&base,&newer,code,length,rm,((op^rm)&1)!=0)) {
						fprintf(stderr,"register text differs at mode %u syntax %u prefix %u opcode %02x ModRM %02x\n",m,syntax,p,op,rm);
						return 8;
					}
					++checks;
				}
			}
		}
		base.close(&base.h);newer.close(&newer.h);
	}
	printf("%u iterator outputs match including poisoned text buffers and text-buffer input aliasing\n",checks);
	dlclose(library);
	return 0;
}
