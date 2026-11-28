#include <capstone/capstone.h>
#include <dlfcn.h>
#include <algorithm>
#include <array>
#include <cctype>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <string>
#include <vector>

using Sets=std::array<std::vector<uint16_t>,2>;
struct Api {
	void *lib;
	decltype(&cs_open) open; decltype(&cs_close) close; decltype(&cs_option) option;
	decltype(&cs_reg_name) name; decltype(&cs_disasm_iter) next; decltype(&cs_regs_access) regs;
	explicit Api(const char *f):lib(dlopen(f,RTLD_NOW|RTLD_LOCAL)) {
		if(!lib) { std::fprintf(stderr,"%s\n",dlerror());std::exit(2); }
#define SYM(dst,fn) if(!(dst=reinterpret_cast<decltype(dst)>(dlsym(lib,#fn))))std::exit(3)
		SYM(open,cs_open);SYM(close,cs_close);SYM(option,cs_option);SYM(name,cs_reg_name);
		SYM(next,cs_disasm_iter);SYM(regs,cs_regs_access);
#undef SYM
	}
	csh handle(unsigned syntax,bool detail,bool text) {
		csh h;if(open(CS_ARCH_LOONGARCH,CS_MODE_LOONGARCH64,&h)||
			option(h,CS_OPT_SYNTAX,syntax)||option(h,CS_OPT_DETAIL,detail?CS_OPT_ON:CS_OPT_OFF)||
			option(h,CS_OPT_TEXT,text?CS_OPT_ON:CS_OPT_OFF))std::exit(4);return h;
	}
};
static void add(std::vector<uint16_t> &dst,unsigned reg) {
	if(std::find(dst.begin(),dst.end(),reg)==dst.end())dst.push_back(uint16_t(reg));
}
static Sets oracle(const cs_detail &d,bool index) {
	Sets out{{{d.regs_read,d.regs_read+d.regs_read_count},{d.regs_write,d.regs_write+d.regs_write_count}}};
	for(unsigned i=0;i<d.loongarch.op_count;++i) {
		auto &o=d.loongarch.operands[i];
		if(o.type==LOONGARCH_OP_REG) {
			if(o.access&CS_AC_READ)add(out[0],o.reg);
			if(o.access&CS_AC_WRITE)add(out[1],o.reg);
		} else if(o.type==LOONGARCH_OP_MEM) {
			if(o.mem.base)add(out[0],o.mem.base);
			if(index&&o.mem.index)add(out[0],o.mem.index);
			if(d.writeback&&o.mem.base)add(out[1],o.mem.base);
		}
	}
	return out;
}
static Sets access(Api &a,csh h,cs_insn &ins) {
	cs_regs rd{},wr{};uint8_t nr=0,nw=0;if(a.regs(h,&ins,rd,&nr,wr,&nw))std::exit(5);
	return Sets{{{rd,rd+nr},{wr,wr+nw}}};
}
static std::string numeric(const char *src,const std::map<std::string,std::string> &names) {
	std::string out;while(*src) {
		if(!std::isalnum(static_cast<unsigned char>(*src))&&*src!='_') {out+=*src++;continue;}
		const char *first=src++;while(std::isalnum(static_cast<unsigned char>(*src))||*src=='_')++src;
		std::string token(first,src);auto pos=names.find(token);out+=pos==names.end()?token:pos->second;
	} return out;
}
int main(int argc,char **argv) {
	if(argc!=6)return 1;
	Api a(argv[1]),b(argv[2]);std::ifstream input(argv[3],std::ios::binary);
	std::vector<uint8_t> data{std::istreambuf_iterator<char>(input),{}};if(data.empty()||data.size()%4)return 6;
	uint64_t base=std::strtoull(argv[4],nullptr,10);int diet=std::atoi(argv[5]);
	csh abi=a.handle(CS_OPT_SYNTAX_DEFAULT,true,true),raw=b.handle(CS_OPT_SYNTAX_NOREGNAME,true,true);
	std::map<std::string,std::string> names;
	if(!diet)for(unsigned k=1;k<LOONGARCH_REG_ENDING;k++) {
		auto x=a.name(abi,k),y=b.name(raw,k);if(!x||!y)return 7;
		auto z=names.emplace(x,y);if(!z.second&&z.first->second!=y)return 8;
	}
	for(unsigned config=0;config<16;config++) {
		unsigned syntax=(config&1?unsigned(CS_OPT_SYNTAX_NOREGNAME):0u)|(config&2?unsigned(CS_OPT_SYNTAX_NO_DOLLAR):0u);
		bool with_detail=config&4,text=config&8;
		csh h=a.handle(syntax,with_detail,text),j=b.handle(syntax,with_detail,text);
		size_t changed_text=0,changed_sets=0,accepted=0,rejected=0,indexed=0;
		for(size_t off=0;off<data.size();off+=4) {
			cs_insn x{},y{};cs_detail dx{},dy{};
			std::memset(&x,0x55,sizeof x);x.is_alias=x.illegal=x.usesAliasDetails=false;std::memcpy(&y,&x,sizeof x);
			std::memset(&dx,0x55,sizeof dx);std::memcpy(&dy,&dx,sizeof dx);
			x.detail=with_detail?&dx:nullptr;y.detail=with_detail?&dy:nullptr;
			auto px=data.data()+off;const uint8_t *l=px,*r=px;size_t ls=4,rs=4;uint64_t ip=base+off,jp=ip;
			bool ok=a.next(h,&l,&ls,&ip,&x);if(b.next(j,&r,&rs,&jp,&y)!=ok||l!=r||ls!=rs||ip!=jp)return 9;
			if(ok){++accepted;if(ls)return 10;}else{++rejected;if(ls!=4)return 11;}
			if(ok&&with_detail&&!diet) {
				auto baseline=access(a,h,x),fixed=access(b,j,y);auto old=oracle(dx,false),target=oracle(dx,true);
				if(old!=baseline||target!=fixed) {std::fprintf(stderr,"access offset %zu\n",off);return 12;}
				changed_sets+=baseline!=fixed;
				for(unsigned i=0;i<dx.loongarch.op_count;++i)
					indexed+=dx.loongarch.operands[i].type==LOONGARCH_OP_MEM && dx.loongarch.operands[i].mem.index;
			}
			if(ok&&text&&!diet&&(config&1)) {
				auto target=numeric(x.op_str,names);if(target!=y.op_str){std::fprintf(stderr,"offset %zu: %s %s | %s | %s\n",off,x.mnemonic,x.op_str,target.c_str(),y.op_str);return 13;}
				changed_text+=std::strcmp(x.op_str,y.op_str)!=0;
				std::memset(x.op_str,0,sizeof x.op_str);std::memcpy(x.op_str,target.data(),std::min(target.size(),sizeof(x.op_str)-1));
			}
			x.detail=y.detail=nullptr;
			if(std::memcmp(&x,&y,sizeof x)||std::memcmp(&dx,&dy,sizeof dx)){std::fprintf(stderr,"record offset %zu cfg %u\n",off,config);return 14;}
		}
		std::printf("%u %zu %zu %zu %zu %zu\n",config,accepted,rejected,changed_text,indexed,changed_sets);a.close(&h);b.close(&j);
	}
	a.close(&abi);b.close(&raw);return 0;
}
