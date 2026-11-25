#include <capstone/capstone.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fstream>
#include <iterator>
#include <memory>
#include <random>
#include <time.h>
#include <vector>

static uint64_t now(clockid_t id)
{
	timespec t;
	if (clock_gettime(id, &t)) std::abort();
	return uint64_t(t.tv_sec) * 1000000000 + t.tv_nsec;
}
struct api {
	void *lib;
	csh handle = 0;
	decltype(&cs_regs_access) access;
	api(const char *file, cs_mode mode) {
		lib = dlopen(file, RTLD_NOW | RTLD_LOCAL);
		if (!lib) std::abort();
		auto open = reinterpret_cast<decltype(&cs_open)>(dlsym(lib,"cs_open"));
		auto option = reinterpret_cast<decltype(&cs_option)>(dlsym(lib,"cs_option"));
		access = reinterpret_cast<decltype(access)>(dlsym(lib,"cs_regs_access"));
		if (!open || !option || !access || open(CS_ARCH_X86,mode,&handle) ||
		    option(handle,CS_OPT_DETAIL,CS_OPT_ON)) std::abort();
	}
	~api() {
		reinterpret_cast<decltype(&cs_close)>(dlsym(lib,"cs_close"))(&handle);
		dlclose(lib);
	}
};
int main(int argc, char **argv)
{
	if (argc != 7) return 1;
	cs_mode mode = std::atoi(argv[6]) == 64 ? CS_MODE_64 : CS_MODE_32;
	api base(argv[1],mode), candidate(argv[2],mode), outlined(argv[3],mode);
	std::array<api*,4> apis{&base,&base,&candidate,&outlined};
	auto alloc = reinterpret_cast<decltype(&cs_malloc)>(dlsym(base.lib,"cs_malloc"));
	auto iter = reinterpret_cast<decltype(&cs_disasm_iter)>(dlsym(base.lib,"cs_disasm_iter"));
	auto release = reinterpret_cast<decltype(&cs_free)>(dlsym(base.lib,"cs_free"));
	if (!alloc || !iter || !release) return 2;
	cs_insn *decoded = alloc(base.handle);
	std::ifstream bin(argv[4],std::ios::binary), spans(argv[5]);
	std::vector<uint8_t> data{std::istreambuf_iterator<char>(bin),{}};
	if (!decoded || data.empty() || !spans) return 3;
	constexpr unsigned block = 256, rounds = 17, laps = 4;
	std::vector<cs_insn> records(block);
	std::vector<cs_detail> details(block);
	unsigned used = 0;
	std::mt19937 random(4321);
	uint64_t accepted=0, first=0, loads=0, signature=0;
	uint64_t times[rounds][4][2]{};
	auto replay = [&] {
		if (!used) return;
		uint64_t expected = 0;
		for (unsigned round=0;round<=rounds;++round) {
			std::array<unsigned,4> order{0,1,2,3};
			std::shuffle(order.begin(),order.end(),random);
			for (auto which:order) {
				const auto &a=*apis[which];
				uint64_t sum=0;
				auto start=now(CLOCK_PROCESS_CPUTIME_ID), wall=now(CLOCK_MONOTONIC);
				for (unsigned repeat=0;repeat<laps;++repeat) {
					for (unsigned i=0;i<used;++i) {
						cs_regs reads,writes; uint8_t nr=0,nw=0;
						if (a.access(a.handle,&records[i],reads,&nr,writes,&nw)) std::abort();
						sum+=nr+129U*nw;
						if (nr) sum+=reads[nr-1];
						if (nw) sum+=writes[nw-1];
					}
				}
				auto ns=now(CLOCK_PROCESS_CPUTIME_ID)-start, elapsed=now(CLOCK_MONOTONIC)-wall;
				if (!round && which==order[0]) expected=sum;
				if (sum!=expected) std::abort();
				if (round) { times[round-1][which][0]+=ns; times[round-1][which][1]+=elapsed; }
			}
		}
		signature+=expected; used=0;
	};
	size_t begin=0,length=0;uint64_t ip;
	while (spans>>begin>>length>>ip) {
		if (!length || begin>data.size() || length>data.size()-begin) return 4;
		const uint8_t *p=data.data()+begin;size_t left=length;
		while (left) {
			if (!iter(base.handle,&p,&left,&ip,decoded)) {++p;--left;++ip;continue;}
			const auto &d=*decoded->detail;const auto &x=d.x86;
			if (!d.regs_read_count && !d.regs_write_count && x.op_count && x.operands[0].type==X86_OP_REG) {
				++first;
				const auto &op=x.operands[1];
				loads+=x.op_count==2 && x.operands[0].access==CS_AC_WRITE && op.type==X86_OP_MEM &&
					!op.mem.segment && !op.mem.index && op.mem.base!=X86_REG_INVALID;
			}
			records[used].id=decoded->id;
			std::memcpy(&details[used],decoded->detail,sizeof(cs_detail));
			records[used].detail=&details[used];++used;++accepted;
			if (used==block) replay();
		}
	}
	replay();release(decoded,1);
	std::printf("%llu %llu %llu %llu\n",(unsigned long long)accepted,(unsigned long long)loads,
		    (unsigned long long)first,(unsigned long long)signature);
	for(const auto &round:times){
		for(const auto &which:round) std::printf("%llu %llu ",(unsigned long long)which[0],(unsigned long long)which[1]);
		std::puts("");
	}
}
