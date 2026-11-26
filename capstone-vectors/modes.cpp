#include <capstone/capstone.h>
#include <array>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

struct Record {
	uint64_t cursor,address;
	unsigned id, size;
	uint8_t bytes[sizeof(cs_insn::bytes)];
	char mnemonic[sizeof(cs_insn::mnemonic)], operands[sizeof(cs_insn::op_str)];
	cs_x86 x86;
	cs_regs reads, writes;
	uint8_t groups[sizeof(cs_detail::groups)],read_count,write_count,group_count;
	bool valid;
};
struct Runner {
	csh h;cs_insn *insn;
	Runner(cs_mode mode,bool reopen,unsigned route,cs_opt_value syntax) {
		if (cs_open(CS_ARCH_X86,reopen?CS_MODE_16:mode,&h)!=CS_ERR_OK) std::exit(2);
		if (reopen && cs_option(h,CS_OPT_MODE,mode)!=CS_ERR_OK) std::exit(2);
		if (cs_option(h,CS_OPT_SYNTAX,syntax)!=CS_ERR_OK ||
		    cs_option(h,CS_OPT_TEXT,route==0 || route==3?CS_OPT_OFF:CS_OPT_ON)!=CS_ERR_OK ||
		    cs_option(h,CS_OPT_DETAIL,route>=2?CS_OPT_ON:CS_OPT_OFF)!=CS_ERR_OK) std::exit(2);
		insn=cs_malloc(h);if (!insn) std::exit(2);
	}
	~Runner(){cs_free(insn,1);cs_close(&h);}
	void read(Record &out,const uint8_t *bytes,size_t size,uint64_t address) {
		auto *detail=insn->detail;std::memset(insn,0,sizeof(*insn));insn->detail=detail;
		if (detail) std::memset(detail,0,sizeof(*detail));
		std::memset(&out,0,sizeof out);auto *p=bytes;auto remain=size;
		out.valid=cs_disasm_iter(h,&p,&remain,&address,insn);
		out.cursor=static_cast<uint64_t>(p-bytes);out.address=address;
		if (!out.valid) return;
		if (!insn->size || out.cursor!=insn->size || remain!=size-insn->size) std::exit(3);
		out.id=insn->id;out.size=insn->size;
		std::memcpy(out.bytes,insn->bytes,insn->size);
		std::memcpy(out.mnemonic,insn->mnemonic,sizeof out.mnemonic);std::memcpy(out.operands,insn->op_str,sizeof out.operands);
		if (detail) {
			std::memcpy(&out.x86,&detail->x86,sizeof out.x86);
			out.group_count=detail->groups_count;std::memcpy(out.groups,detail->groups,out.group_count);
			if (cs_regs_access(h,insn,out.reads,&out.read_count,out.writes,&out.write_count)!=CS_ERR_OK) std::exit(4);
		}
	}
};
int main() {
	const std::array<std::array<uint8_t,15>,12> examples={{
		{0x66,0x48,0xd9,0x30},{0x0f,0x31},{0x0f,0x01,0xf9},{0x50},{0xc3},
		{0xe8,0x78,0x56,0x34,0x12},{0xa0,0x34,0x82,0x00,0x80,0xec,0xcd,0xbc,0xbc},
		{0x67,0xa0,0xff,0xff,0xff,0xff},{0x48,0x8b,0x44,0x24,0x38},
		{0x62,0xf1,0x7d,0xc9,0x6f,0xc1},{0x0f,0x85,0xfe,0xff,0xff,0xff},{0x66,0x48,0xdd,0x30}
	}};
	Record actual,want;unsigned shown=0;uint64_t rows=0,valid=0,bad=0,changes[4]={};
	for (bool change:{false,true}) for (unsigned vendor:{0u,unsigned(CS_MODE_X86_INTEL),unsigned(CS_MODE_X86_AMD)})
		for (auto syntax:{CS_OPT_SYNTAX_INTEL,CS_OPT_SYNTAX_ATT,CS_OPT_SYNTAX_MASM}) for(unsigned route=0;route<4;++route) {
			Runner a(static_cast<cs_mode>(vendor),change,route,syntax),b(static_cast<cs_mode>(CS_MODE_64|vendor),change,route,syntax);
			uint32_t rng=0x67241234;
			for (unsigned n=0;n<4096+examples.size();++n) {
				std::array<uint8_t,15> data;
				if (n<examples.size()) data=examples[n];
				else { for(auto &v:data){rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;v=static_cast<uint8_t>(rng);}
					if ((n&7)==1)data[0]=0x0f;
					if ((n&7)==2)data[0]=0x67;
					if ((n&7)==3){data[0]=0x66;data[1]=0x48;}
				}
				size_t length=n<examples.size()?15:1+(n%15);
				uint64_t ip=UINT64_C(0x104088abcdf0)+n;
				a.read(actual,data.data(),length,ip);b.read(want,data.data(),length,ip);
				++rows;valid+=want.valid;
				if (std::memcmp(&actual,&want,sizeof actual)!=0) {
					++bad;
					unsigned kind=actual.valid!=want.valid || actual.cursor!=want.cursor?0:actual.id!=want.id?1:
						std::strcmp(actual.mnemonic,want.mnemonic)||std::strcmp(actual.operands,want.operands)?2:3;
					++changes[kind];
					if (shown<10 && n<examples.size()) {
						++shown;std::fprintf(stderr,"example %u vendor=%u syntax=%u route=%u kind=%u <%s %s> <%s %s>\n",
							n,vendor,unsigned(syntax),route,kind,actual.mnemonic,actual.operands,want.mnemonic,want.operands);
					}
				}
			}
		}
	std::printf("%" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",
		rows,valid,bad,changes[0],changes[1],changes[2],changes[3]);
}
