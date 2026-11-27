#include <capstone/capstone.h>
#include <dlfcn.h>
#include <array>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

struct Api {
	explicit Api(const char *path) : lib(dlopen(path, RTLD_NOW | RTLD_LOCAL)) {
		if (!lib) std::abort();
	}
	void *lib;
	template<class T> T lookup(const char *name) {
		auto p = dlsym(lib, name);
		if (!p) std::abort();
		return reinterpret_cast<T>(p);
	}
	decltype(&cs_open) open = lookup<decltype(open)>("cs_open");
	decltype(&cs_close) close = lookup<decltype(close)>("cs_close");
	decltype(&cs_option) option = lookup<decltype(option)>("cs_option");
	decltype(&cs_disasm_iter) next = lookup<decltype(next)>("cs_disasm_iter");
};
struct Step {
	std::string fmt, output;
	cs_x86 operands;
};
struct Record {
	cs_insn insn;
	cs_detail detail;
	std::vector<Step> trace;
	size_t remaining{};
	uint64_t next_ip{};
	bool accepted{};
};
static cs_opt_mem defaults{std::malloc,std::calloc,std::realloc,std::free,std::vsnprintf};
static Api *active;
static Record *record;
static int policy;
static int callback(char *dst, size_t cap, const char *fmt, va_list arguments)
{
	const int n=std::vsnprintf(dst,cap,fmt,arguments);
	const size_t index=record->trace.size();
	record->trace.push_back({fmt,n<0?"":dst,record->detail.x86});
	if (policy==2 || (policy==3 && index==1)) {
		if (active->option(0,CS_OPT_MEM,reinterpret_cast<size_t>(&defaults))) std::abort();
	}
	if (policy>=3) {
		const unsigned written=record->detail.x86.op_count;
		for (unsigned j=written; j<8; ++j)
			record->detail.x86.operands[j].access=static_cast<cs_ac_type>(0x40+j);
		record->detail.x86.eflags=0xcdef;
	}
	return policy==5 && !(index%2) ? -1 : n;
}
static void run(Api &api,cs_mode mode, const std::vector<uint8_t> &data,Record &out)
{
	csh h;
	if (api.option(0,CS_OPT_MEM,reinterpret_cast<size_t>(&defaults)) || api.open(CS_ARCH_X86,mode,&h) ||
	    api.option(h,CS_OPT_DETAIL,CS_OPT_ON) || api.option(h,CS_OPT_SYNTAX,CS_OPT_SYNTAX_ATT)) std::abort();
	cs_opt_mem custom=defaults;custom.vsnprintf=callback;
	active=&api;record=&out;
	std::memset(&out.insn,0xa5,sizeof(out.insn));
	std::memset(&out.detail,0xa5,sizeof(out.detail));
	out.insn.detail=&out.detail;
	if (policy && api.option(0,CS_OPT_MEM,reinterpret_cast<size_t>(&custom))) std::abort();
	auto p=data.data();out.remaining=data.size();out.next_ip=0x12345678;
	out.accepted=api.next(h,&p,&out.remaining,&out.next_ip,&out.insn);
	out.insn.detail=nullptr;
	if (api.option(0,CS_OPT_MEM,reinterpret_cast<size_t>(&defaults)) || api.close(&h)) std::abort();
}
int main(int argc,char **argv)
{
	if (argc!=3) return 1;
	Api base(argv[1]),trial(argv[2]);
	std::vector<std::vector<uint8_t>> inputs={
		{0x89,0xd8},{0x8b,0x44,0x8d,0x12},{0x67,0x8b,0x06,0x34,0x82},
		{0x64,0x8a,0x04,0x25,0x3a,0,0,0},{0xa4},{0xa5},{0xf3,0xa7},{0xaa},
		{0xac},{0x66,0x0f,0x3a,0x0f,0xcc,0x05},{0xd1,0xe8},{0xd0,0x20},
		{0x04,0xee},{0x05,0xee,0,0,0},{0x0f,0xa2},{0xff,0xd2},
		{0x62,0xf1,0x7d,0x49,0x6f,0xc8},{0x0f,0xb9,0xc4},{0x0f,0xb1,0x11},
		{0x0f,0x58,0xc1},{0xc5,0xf9,0x6f,0xc1},{0x48,0x83,0x63,0xf0,0xff}
	};
	unsigned cases=0, accepted=0, hooks=0, with_register=0;
	for (auto mode:{CS_MODE_16,CS_MODE_32,CS_MODE_64}) for (policy=0;policy<=5;++policy)
	for (auto &data:inputs) {
		Record a{},b{};run(base,mode,data,a);run(trial,mode,data,b);
		if (a.accepted!=b.accepted || a.next_ip!=b.next_ip || a.remaining!=b.remaining ||
		    a.trace.size()!=b.trace.size() || std::memcmp(&a.insn,&b.insn,sizeof(a.insn)) ||
		    std::memcmp(&a.detail,&b.detail,sizeof(a.detail))) {
			std::fprintf(stderr,"record case=%u mode=%d policy=%d opcode=%x trace=%zu/%zu\n",cases,mode,policy,data[0],a.trace.size(),b.trace.size());return 2;
		}
		for (size_t j=0;j<a.trace.size();++j) {
			auto &x=a.trace[j],&y=b.trace[j];
			if(x.fmt!=y.fmt || x.output!=y.output || std::memcmp(&x.operands,&y.operands,sizeof(x.operands))) {
				std::fprintf(stderr,"trace case=%u callback=%zu mode=%d policy=%d opcode=%x fmt=%s\n",cases,j,mode,policy,data[0],x.fmt.c_str());return 3;
			}
			++hooks;with_register+=x.fmt=="%%%s";
		}
		++cases;accepted+=a.accepted;
	}
	if (!hooks || !accepted || !with_register) return 4;
	std::printf("{\"cases\":%u,\"accepted\":%u,\"callbacks\":%u,\"register_formats\":%u}\n",cases,accepted,hooks,with_register);
}
