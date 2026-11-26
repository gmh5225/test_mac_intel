#include <capstone/capstone.h>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

using Bytes = std::vector<uint8_t>;
static Bytes load(const char *p) {
	std::ifstream in(p, std::ios::binary);
	if (!in) std::exit(1);
	return {std::istreambuf_iterator<char>(in), {}};
}
static uint32_t little32(const uint8_t *x) {
	return uint32_t(x[0]) | (uint32_t(x[1])<<8) | (uint32_t(x[2])<<16) | (uint32_t(x[3])<<24);
}
static void digest(uint64_t &h, const void *p, size_t size) {
	auto *bytes=static_cast<const uint8_t *>(p);
	for (size_t i=0; i<size; ++i) h=(h ^ bytes[i])*1099511628211ULL;
}
int main(int argc,char **argv) {
	if (argc!=6) return 1;
	auto code=load(argv[1]), input=load(argv[2]);
	struct Range { uint32_t start, bytes; };
	std::vector<Range> ranges;
	if (input.size()%8) return 2;
	for (size_t i=0;i<input.size();i+=8) {
		Range v={little32(&input[i]), little32(&input[i+4])};
		if (!v.bytes || uint64_t(v.start)+v.bytes>code.size()) return 3;
		ranges.push_back(v);
	}
	bool detail=std::atoi(argv[3])!=0, verify=std::atoi(argv[4])!=0;
	unsigned repeats=std::atoi(argv[5]);
	csh handle;
	if (cs_open(CS_ARCH_WASM,static_cast<cs_mode>(0),&handle)!=CS_ERR_OK) return 4;
	if (cs_option(handle,CS_OPT_DETAIL,detail ? CS_OPT_ON : CS_OPT_OFF)!=CS_ERR_OK) return 5;
	auto *insn=cs_malloc(handle);
	if (!insn) return 6;
	uint64_t accepted=0,short_record=0,refused=0,h=0xcbf29ce484222325ULL;
	auto start=std::chrono::steady_clock::now();
	auto cpu=std::clock();
	for (unsigned rep=0;rep<repeats;++rep)
		for (const auto &range:ranges) {
			auto *ptr=static_cast<const uint8_t *>(code.data()+range.start);
			uint64_t address=range.start;
			size_t length=range.bytes;
			if (!cs_disasm_iter(handle,&ptr,&length,&address,insn)) {
				++refused;
				if (verify) digest(h,&range.start,sizeof(range.start));
				continue;
			}
			if (length) ++short_record; else ++accepted;
			if (verify) {
				if (!insn->size || insn->size>range.bytes || address!=uint64_t(range.start)+insn->size ||
				    ptr!=code.data()+range.start+insn->size || length!=range.bytes-insn->size || insn->address!=range.start)
					return 7;
				digest(h,&insn->address,sizeof(insn->address));digest(h,&insn->size,sizeof(insn->size));digest(h,&insn->id,sizeof(insn->id));
				digest(h,insn->bytes,insn->size<sizeof(insn->bytes)?insn->size:sizeof(insn->bytes));
				digest(h,insn->mnemonic,std::strlen(insn->mnemonic)+1);digest(h,insn->op_str,std::strlen(insn->op_str)+1);
				if (detail) {
					const auto *d=insn->detail;
					digest(h,&d->regs_read_count,sizeof(d->regs_read_count));digest(h,d->regs_read,d->regs_read_count*sizeof(*d->regs_read));
					digest(h,&d->regs_write_count,sizeof(d->regs_write_count));digest(h,d->regs_write,d->regs_write_count*sizeof(*d->regs_write));
					digest(h,&d->groups_count,sizeof(d->groups_count));digest(h,d->groups,d->groups_count*sizeof(*d->groups));
					digest(h,&d->wasm,sizeof(d->wasm));
				}
			} else h+=insn->id+insn->size;
		}
	auto ns=std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now()-start).count();
	auto cpu_ns=static_cast<uint64_t>(1e9*(std::clock()-cpu)/CLOCKS_PER_SEC);
	std::printf("%llu %llu %llu %llu %llu %llu\n",(unsigned long long)cpu_ns,(unsigned long long)ns,
	            (unsigned long long)accepted,(unsigned long long)short_record,(unsigned long long)refused,(unsigned long long)h);
	cs_free(insn,1);cs_close(&handle);
}
