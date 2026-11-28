#include <capstone/capstone.h>
#include <dlfcn.h>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <vector>

struct API {
	void *lib;
	decltype(&cs_open) open;decltype(&cs_close) close;decltype(&cs_option) option;
	decltype(&cs_disasm_iter) next;decltype(&cs_errno) error;
	API(const char *p):lib(dlopen(p,RTLD_LOCAL|RTLD_NOW)) {
		if(!lib){std::fprintf(stderr,"%s\n",dlerror());std::exit(2);}
#define L(m,n) if(!(m=reinterpret_cast<decltype(m)>(dlsym(lib,#n))))std::exit(2)
		L(open,cs_open);L(close,cs_close);L(option,cs_option);L(next,cs_disasm_iter);L(error,cs_errno);
#undef L
	}
};
struct Reader {
	API &api;csh h{};
	Reader(API &a,size_t view,bool print):api(a){
		if(api.open(CS_ARCH_LOONGARCH,CS_MODE_LOONGARCH64,&h)||api.option(h,CS_OPT_DETAIL,view)||
		   api.option(h,CS_OPT_TEXT,print?CS_OPT_ON:CS_OPT_OFF))std::exit(3);
	}
	~Reader(){api.close(&h);}
};
static void fail(const char *reason,size_t off) {std::fprintf(stderr,"%s at %zu\n",reason,off);std::exit(4);}
int main(int argc,char **argv) {
	if(argc!=6)return 1;
	API old(argv[1]),now(argv[2]);bool diet=std::atoi(argv[5]);std::ifstream file(argv[3],std::ios::binary);
	std::vector<uint8_t> data{std::istreambuf_iterator<char>(file),{}};
	uint64_t start=strtoull(argv[4],nullptr,10);
	for(bool text:{false,true}) {
		Reader ref(old,CS_OPT_DETAIL_REAL,text),fixed(now,CS_OPT_DETAIL_REAL,text),alias(old,CS_OPT_DETAIL_ALIAS,text);
		std::array<Reader*,3> readers={&ref,&fixed,&alias};
		uint64_t count=0,operands=0,groups=0;
		for(size_t off=0;off<data.size();off+=4) {
			const uint8_t *code=data.data()+off;uint32_t word=uint32_t(code[0])|(uint32_t(code[1])<<8)|(uint32_t(code[2])<<16)|(uint32_t(code[3])<<24);
			std::array<cs_insn,3> insns{};std::array<cs_detail,3> ds{};std::array<bool,3> ok{};
			for(size_t k=0;k<3;++k) {
				auto &ins=insns[k];std::memset(&ins,0x55,sizeof(ins));ins.is_alias=ins.illegal=ins.usesAliasDetails=false;
				auto &d=ds[k];std::memset(&d,0x55,sizeof(d));ins.detail=&d;
				auto *p=code;size_t n=4;uint64_t ip=start+off;Reader &r=*readers[k];ok[k]=r.api.next(r.h,&p,&n,&ip,&ins);
				if(r.api.error(r.h)!=CS_ERR_OK||p!=code+(ok[k]?4:0)||n!=(ok[k]?0:4)||ip!=start+off+(ok[k]?4:0))fail("cursor",off);
				ins.detail=nullptr;
			}
			if(ok[0]!=ok[1]||ok[0]!=ok[2]||std::memcmp(&insns[0],&insns[1],sizeof(cs_insn)))fail("instruction",off);
			if(ok[0]) {
				++count;auto &d=ds[0];auto &o=d.loongarch;
				if(insns[0].is_alias&&!diet) {
					const unsigned prefix=ds[2].loongarch.op_count;
					if(o.op_count!=prefix+3)fail("canonical operand count",off);
					if(prefix) {
						if(insns[0].id!=LOONGARCH_INS_OR&&insns[0].id!=LOONGARCH_INS_JIRL)fail("unrecognized alias",off);
						if(std::memcmp(o.operands,ds[2].loongarch.operands,prefix*sizeof(o.operands[0])))fail("alias operands",off);
						std::memmove(o.operands,o.operands+prefix,3*sizeof(o.operands[0]));
						std::memset(o.operands+3,0,prefix*sizeof(o.operands[0]));o.op_count=3;++operands;
					}
				}
				if(text&&!diet&&insns[0].id==LOONGARCH_INS_JIRL) {
					if((word>>26)!=0x13)fail("encoding",off);
					const auto rd=word&31,j=(word>>5)&31,imm=(word>>10)&0xffff;
					const unsigned target=rd==1?LOONGARCH_GRP_CALL:rd==0&&j==1&&imm==0?LOONGARCH_GRP_RET:LOONGARCH_GRP_JUMP;
					if(d.groups_count!=1||d.groups[0]!=target){++groups;d.groups_count=1;d.groups[0]=target;}
				}
			}
			if(std::memcmp(&ds[0],&ds[1],sizeof(cs_detail))) {
 std::fprintf(stderr,"text=%u word=%08x alias=%u/%u %s group=%u,%u/%u,%u counts=%u,%u,%u\n",text,word,insns[0].is_alias,insns[2].is_alias,insns[1].mnemonic,ds[0].groups_count,ds[0].groups[0],ds[1].groups_count,ds[1].groups[0],ds[0].loongarch.op_count,ds[1].loongarch.op_count,ds[2].loongarch.op_count);
 auto *x=(const unsigned char*)&ds[0],*y=(const unsigned char*)&ds[1];for(size_t i=0;i<sizeof(cs_detail);++i)if(x[i]!=y[i])std::fprintf(stderr,"%zu:%02x/%02x ",i,x[i],y[i]);std::fputs("\n",stderr);
 fail("detail",off);
}
		}
		std::printf("%u %llu %llu %llu\n",text,(unsigned long long)count,(unsigned long long)operands,(unsigned long long)groups);
	}
}
