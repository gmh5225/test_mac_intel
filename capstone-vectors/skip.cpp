#include <capstone/capstone.h>
#include <dlfcn.h>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

struct Api {
	void *lib;
	explicit Api(const char *path):lib(dlopen(path,RTLD_NOW|RTLD_LOCAL)) { if(!lib)std::abort(); }
	template<typename T> T get(const char *name) { auto x=dlsym(lib,name);if(!x)std::abort();return reinterpret_cast<T>(x); }
	decltype(&cs_open) open=get<decltype(open)>("cs_open");
	decltype(&cs_option) option=get<decltype(option)>("cs_option");
	decltype(&cs_disasm_iter) read=get<decltype(read)>("cs_disasm_iter");
	decltype(&cs_errno) error=get<decltype(error)>("cs_errno");
	decltype(&cs_close) close=get<decltype(close)>("cs_close");
};
struct Callback {
	Api *api;
	csh h;
	unsigned policy;
	std::vector<std::array<uint64_t,3>> trace;
};
static size_t skip(const uint8_t *p,size_t n,size_t offset,void *u)
{
	auto &c=*static_cast<Callback *>(u);
	c.trace.push_back({n,offset,n?p[0]:0U});
	if(c.policy&4) {
		if(c.api->option(c.h,CS_OPT_DETAIL,(c.trace.size()&1)?CS_OPT_OFF:CS_OPT_ON))std::abort();
		if(c.api->option(c.h,CS_OPT_MODE,(c.trace.size()&1)?CS_MODE_32:CS_MODE_64))std::abort();
	}
	switch(c.policy&3) {case 0:return 0;case 1:return 1;case 2:return n;default:return n+1;}
}
struct Record {
	cs_insn insn;
	cs_detail detail;
	size_t offset,remaining;
	uint64_t ip;
	cs_err error;
	bool decoded, restored;
};
struct Replay {std::vector<Record> records;std::vector<std::array<uint64_t,3>> calls;};
static Replay run(Api &api,cs_mode mode,unsigned policy,unsigned settings,const std::vector<uint8_t>& input)
{
	csh h;if(api.open(CS_ARCH_X86,mode,&h))std::abort();
	Callback cb{&api,h,policy,{}};cs_opt_skipdata setup{"bad-byte",skip,&cb};
	if(api.option(h,CS_OPT_DETAIL,(settings&1)?CS_OPT_ON:CS_OPT_OFF) ||
	   api.option(h,CS_OPT_TEXT,(settings&2)?CS_OPT_OFF:CS_OPT_ON) ||
	   api.option(h,CS_OPT_SYNTAX,(settings&4)?CS_OPT_SYNTAX_ATT:CS_OPT_SYNTAX_INTEL) ||
	   api.option(h,CS_OPT_SKIPDATA_SETUP,reinterpret_cast<size_t>(&setup)) ||
	   api.option(h,CS_OPT_SKIPDATA,CS_OPT_ON))std::abort();
	cs_insn insn;cs_detail detail;std::memset(&insn,0xa5,sizeof(insn));std::memset(&detail,0xa5,sizeof(detail));insn.detail=&detail;
	Replay out;auto p=input.data();size_t n=input.size();uint64_t ip=0x87654321;
	do {
		bool ok=api.read(h,&p,&n,&ip,&insn);Record step{};
		std::memcpy(&step.insn,&insn,sizeof(insn));step.insn.detail=nullptr;
		std::memcpy(&step.detail,&detail,sizeof(detail));step.offset=p-input.data();step.remaining=n;step.ip=ip;
		step.error=api.error(h);step.decoded=ok;step.restored=insn.detail==&detail;
		out.records.push_back(step);
		if(!ok)break;
		if(out.records.size()>input.size())std::abort();
	}while(n);
	out.calls=cb.trace;if(api.close(&h))std::abort();return out;
}
int main(int argc,char **argv)
{
	if(argc!=3)return 1;
	Api base(argv[1]),candidate(argv[2]);
	std::vector<std::vector<uint8_t>> blocks={{0x8b,0x44,0x24,0x20,0x0f},{0x66,0x0f},{0xc5,0xf8,0x77,0xf3,0xc5},{0xff,0xd2,0x90,0x0f},{0x0f}};
	std::vector<uint8_t> long_form(16,0x66);long_form.insert(long_form.end(),{0x90,0x40,0x8b,0x00,0x0f});blocks.push_back(long_form);
	unsigned cases=0, calls=0, records=0;
	for(auto mode:{CS_MODE_16,CS_MODE_32,CS_MODE_64})for(unsigned policy=0;policy<8;++policy)
	for(unsigned settings=0;settings<8;++settings)for(auto& block:blocks){
		auto a=run(base,mode,policy,settings,block),b=run(candidate,mode,policy,settings,block);
		if(a.calls!=b.calls||a.records.size()!=b.records.size())return 2;
		for(size_t i=0;i<a.records.size();++i){
			auto &x=a.records[i],&y=b.records[i];
			if(std::memcmp(&x.insn,&y.insn,sizeof(x.insn))||std::memcmp(&x.detail,&y.detail,sizeof(x.detail))||
			   x.ip!=y.ip||x.remaining!=y.remaining||x.offset!=y.offset||x.error!=y.error||
			   x.restored!=y.restored||x.decoded!=y.decoded) {
				std::fprintf(stderr,"mode=%d settings=%u policy=%u case=%u record=%zu\n",mode,settings,policy,cases,i);return 3;
			}
		}
		++cases;calls+=a.calls.size();records+=a.records.size();
	}
	if(cases!=1152||!calls)return 4;
	std::printf("{\"cases\":%u,\"steps\":%u,\"callbacks\":%u}\n",cases,records,calls);
}
