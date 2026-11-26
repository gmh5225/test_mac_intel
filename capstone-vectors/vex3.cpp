#include "arch/X86/X86ScanAdapter.h"
#include <capstone/capstone.h>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

int main()
{
	const size_t page=size_t(sysconf(_SC_PAGESIZE));
	auto *mapping=static_cast<uint8_t *>(mmap(nullptr,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0));
	if (mapping==MAP_FAILED || mprotect(mapping+page,page,PROT_NONE)) return 1;
	csh h;
	if (cs_open(CS_ARCH_X86,CS_MODE_32,&h) || cs_option(h,CS_OPT_TEXT,CS_OPT_OFF))return 2;
	auto *insn=cs_malloc(h);if (!insn)return 3;
	uint8_t bytes[15]={0xc4,0xe3,0x7d,0x46,0x44,0x55,0x80,0x76,0x41,0xc0,0x21,0x93,0x00,0x75,0xc7};
	uint64_t n=0,ok=0,hash=0;
	auto probe=[&](size_t len){
		uint8_t *where=mapping+page-len;std::memcpy(where,bytes,len);
		const uint8_t *pos=where;size_t remain=len;uint64_t address=UINT64_MAX-5;
		const bool decoded=cs_disasm_iter(h,&pos,&remain,&address,insn);
		uint32_t out[2]={0xb7a34cde,0xa5e865cd};
		const auto batch=X86_scanNativeBatch(h,where,len,UINT64_MAX-5,out,1);
		uint32_t expected=decoded ? (insn->id<<8)|insn->size : 0xb7a34cde;
		if (batch.count!=unsigned(decoded) || out[0]!=expected || out[1]!=0xa5e865cd ||
		    batch.bytes!=size_t(pos-where) || batch.bytes!=len-remain || address!=UINT64_MAX-5+batch.bytes) {
			for(size_t i=0;i<len;++i)std::fprintf(stderr,"%02x",where[i]);
			std::fprintf(stderr," len=%zu expected=%08x/%zu got=%08x/%zu\n",len,expected,len-remain,out[0],batch.bytes);std::exit(4);
		}
		++n;ok+=decoded;hash=hash*131+batch.bytes+out[0];
	};
	for (unsigned op=0;op<256;++op) for(unsigned payload=0;payload<256;++payload)for(unsigned mr=0;mr<256;++mr) {
		bytes[2]=uint8_t(payload);bytes[3]=uint8_t(op);bytes[4]=uint8_t(mr);bytes[5]=uint8_t(mr*53+payload+op);
		probe(15);probe((mr+op+payload)%13);
	}
	const uint8_t ops[]={0,0x0f,0x38,0x46,0x4e,0x7f};
	const uint8_t mods[]={0x04,0x44,0x85,0xff};
	for(unsigned prefix=0;prefix<256;++prefix)for(unsigned nibble=0;nibble<16;++nibble)
		for(uint8_t op:ops)for(uint8_t mr:mods)for(unsigned len=0;len<16;++len) {
			bytes[1]=uint8_t(prefix);bytes[2]=uint8_t(nibble|(nibble<<4));
			bytes[3]=op;bytes[4]=mr;bytes[5]=uint8_t(13*op+prefix+len);probe(len);
		}
	std::printf("%" PRIu64 " %" PRIu64 " %" PRIu64 "\n",n,ok,hash);
	cs_free(insn,1);cs_close(&h);return munmap(mapping,2*page)!=0;
}
