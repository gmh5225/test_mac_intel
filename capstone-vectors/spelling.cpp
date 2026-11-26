#include <capstone/capstone.h>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <initializer_list>

int main()
{
	unsigned checks = 0, wrong = 0, metadata = 0;
    std::vector<uint64_t> values{0,1,8,9,10,15,16,127,128,0x8000000000000000ULL,0x9fffffffffffffffULL,UINT64_MAX};
    for (unsigned shift=0;shift<64;shift+=4) for (uint64_t first=1;first<=15;++first) {
        values.push_back(first<<shift);
        values.push_back((first<<shift) | ((UINT64_C(1)<<shift)-1));
    }

	for (unsigned mode : {0u, unsigned(CS_MODE_16), unsigned(CS_MODE_32), unsigned(CS_MODE_64)}) {
		const unsigned bits = mode==CS_MODE_16 ? 16 : mode==CS_MODE_32 ? 32 : 64;
		csh h;
		if (cs_open(CS_ARCH_X86, static_cast<cs_mode>(mode), &h)) return 2;
		for (auto syntax : {CS_OPT_SYNTAX_INTEL, CS_OPT_SYNTAX_ATT, CS_OPT_SYNTAX_MASM}) {
			cs_err err=cs_option(h, CS_OPT_SYNTAX, syntax);
			if (err==CS_ERR_X86_ATT && syntax==CS_OPT_SYNTAX_ATT) continue;
			if (err) return 3;
			for (unsigned detail : {0u,1u}) for (unsigned unsign : {0u,1u}) {
				if (cs_option(h,CS_OPT_DETAIL,detail?CS_OPT_ON:CS_OPT_OFF) || cs_option(h,CS_OPT_UNSIGNED,unsign?CS_OPT_ON:CS_OPT_OFF)) return 4;
				for (unsigned ov : {0u,1u}) for (unsigned seg : {0u,0x64u}) for (unsigned opfx : {0u,0x66u,0x48u}) for (unsigned op = 0xa0; op <= 0xa3; ++op) {
					if (opfx==0x48 && bits!=64) continue;
					const unsigned addrbytes=(ov?(bits==32?16:32):bits)/8;
					const uint64_t mask=UINT64_MAX>>(64-8*addrbytes);
					for (uint64_t raw : values) {
						const uint64_t expected = raw & mask;
						unsigned n=0;
						uint8_t code[16];
						if (seg) code[n++]=seg;
						if (ov) code[n++]=0x67;
						if (opfx) code[n++]=opfx;
						code[n++]=op;
						unsigned offset=n;
						for(unsigned i=0;i<addrbytes;++i)code[n++]=uint8_t(raw>>(8*i));
						cs_insn *insn=nullptr;
						if (cs_disasm(h,code,n,0x400000,1,&insn)!=1 || insn->size!=n) return 5;
						const std::string s=insn->op_str;
						std::string num;
						if (syntax!=CS_OPT_SYNTAX_ATT) {
							auto l=s.find('['),z=s.find(']',l);if (l==s.npos || z==s.npos) return 6;
							num=s.substr(l+1,z-l-1);
						} else {
							auto comma=s.find(", ");if (comma==s.npos) return 7;
							num=(op&2)?s.substr(comma+2):s.substr(0,comma);
							auto colon=num.find(':');if(colon!=num.npos)num=num.substr(colon+1);
						}
                        char hex[32];
                        std::snprintf(hex,sizeof hex,"%" PRIx64,expected);
                        std::string wanted;
                        if(expected<10) wanted=std::to_string(expected);
                        else if(syntax==CS_OPT_SYNTAX_MASM) wanted=(hex[0]>='a' ? std::string("0") : std::string())+hex+"h";
                        else wanted=std::string("0x")+hex;
                        if(num!=wanted){if(wrong<10)std::fprintf(stderr,"spelling %s expected %s\n",num.c_str(),wanted.c_str());++wrong;}
						int base=0;
						if (!num.empty() && num.back()=='h') {num.pop_back();base=16;}
						char *end=nullptr;
						uint64_t found=std::strtoull(num.c_str(),&end,base);
						if (num.empty()||*end||found!=expected) {
							if (wrong<15) std::fprintf(stderr,"%u %u %u %02x data=%02x wanted=%" PRIx64 " got=%s\n",mode,unsigned(syntax),addrbytes,op,opfx,expected,s.c_str());
							++wrong;
						}
						if (detail) {
							const cs_x86 &x=insn->detail->x86;
							unsigned j=0;for (;j<x.op_count;++j) if(x.operands[j].type==X86_OP_MEM) break;
							if(j==x.op_count || (uint64_t(x.operands[j].mem.disp)&mask)!=expected || x.addr_size!=addrbytes || x.encoding.disp_offset!=offset || x.encoding.disp_size!=addrbytes) ++metadata;
						}
						++checks;
						cs_free(insn,1);
					}
				}
			}
		}
		cs_close(&h);
	}
	std::printf("%u %u %u\n",checks,wrong,metadata);
	return 0;
}
