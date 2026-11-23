#include "arch/X86/X86ScanAdapter.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <string>
#include <tuple>
#include <vector>

extern "C" void census_reset();
extern "C" int census_calls();
#include <sstream>
using Reader = bool (*)(csh,const uint8_t **,size_t *,uint64_t *,cs_insn *);
struct Bucket { size_t count{}; std::string first; };
static void compare_mask(csh normal, csh fast, Reader next, unsigned bits, const uint8_t *p,
                         const cs_insn &ref, std::map<std::string, Bucket> &totals)
{
    if (bits != 64 || ref.size < 6 || ref.size > 15 || p[0] != 0x62 || !(p[3] & 7))
        return;
    uint8_t unmasked[15]{};
    std::memcpy(unmasked,p,ref.size); unmasked[3] &= 0x78;
    const auto decode = [&](Reader reader,csh h,cs_insn &rec,cs_detail &d) {
        const uint8_t *begin=unmasked;
        size_t left=ref.size;
        uint64_t ip=ref.address;
        rec.detail=&d;
        return reader(h,&begin,&left,&ip,&rec) && !left;
    };
    cs_insn oracle{},actual{};cs_detail od{},ad{};
    const bool valid=decode(cs_disasm_iter,normal,oracle,od);
    census_reset();
    const bool other=decode(next,fast,actual,ad);
    const int generic=census_calls();
    if (other!=valid || generic>1) std::abort();
    if(valid) {
        actual.detail=oracle.detail;
        if(std::memcmp(&oracle,&actual,sizeof(oracle)) || std::memcmp(&od,&ad,sizeof(od))) std::abort();
    }
    const auto &x=ref.detail->x86;
    std::string mask=" {k"+std::to_string(p[3]&7)+"}";
    if(p[3]&0x80)mask+=" {z}";
    std::string text=ref.op_str;
    const auto pos=text.find(mask);
    if(pos!=std::string::npos)text.erase(pos,mask.size());
    const bool text_match=valid && pos!=std::string::npos && text==oracle.op_str;
    cs_detail normalized;std::memcpy(&normalized,ref.detail,sizeof(normalized));
    auto &nx=normalized.x86;
    const unsigned mask_reg=X86_REG_K0+(p[3]&7);
    unsigned k=0;
    while(k<x.op_count && !(x.operands[k].type==X86_OP_REG && unsigned(x.operands[k].reg)==mask_reg))++k;
    const int mask_pos=k<x.op_count?int(k):-1;
    const int ma=mask_pos<0?-1:int(x.operands[k].access);
    const int ms=mask_pos<0?-1:int(x.operands[k].size);
    const bool mz=mask_pos>=0 && x.operands[k].avx_zero_opmask;
    nx.opcode[3]=unmasked[3];
    if(mask_pos>=0) {
        std::memmove(nx.operands+k,nx.operands+k+1,(nx.op_count-k-1)*sizeof(nx.operands[0]));
        std::memset(&nx.operands[--nx.op_count],0,sizeof(nx.operands[0]));
    }
    const auto original_dst=nx.operands[0].access;
    for(unsigned i=0;i<nx.op_count;i++)nx.operands[i].avx_zero_opmask=false;
    const bool raw=valid && ref.id==oracle.id && !std::memcmp(&normalized,&od,sizeof(od));
    nx.operands[0].access=od.x86.operands[0].access;
    const bool adjusted=valid && ref.id==oracle.id && !std::memcmp(&normalized,&od,sizeof(od));
    const bool reg=(p[5]>>6)==3;
    std::string addr=reg?"reg":"mem";
    for(unsigned i=0;i<x.op_count;i++)if(x.operands[i].type==X86_OP_MEM){
        const auto &mem=x.operands[i].mem;
        addr=mem.base==X86_REG_RIP?"rip":mem.index!=X86_REG_INVALID?"indexed":mem.base==X86_REG_INVALID?"absolute":"base";break;
    }
    std::ostringstream key,first;
    key<<ref.mnemonic<<'\t'<<unsigned(p[4])<<'\t'<<addr<<'\t'<<bool(p[3]&0x80)<<'\t'<<valid<<'\t'<<(valid && !generic)<<'\t'<<text_match<<'\t'<<raw<<'\t'<<adjusted<<'\t'<<mask_pos<<'\t'<<ma<<'\t'<<ms<<'\t'<<mz<<'\t'<<unsigned(original_dst)<<'\t'<<unsigned(od.x86.operands[0].access);
    auto &b=totals[key.str()];if(!b.count){
        static constexpr char digit[]="0123456789abcdef";
        for(unsigned i=0;i<ref.size;i++)first<<digit[p[i]>>4]<<digit[p[i]&15];
        first<<'\t'<<ref.op_str<<'\t'<<(valid?oracle.op_str:"(invalid)");b.first=first.str();
    }
    ++b.count;
}

int main(int argc, char **argv)
{
	if (argc != 5) return 1;
	const unsigned bits = std::atoi(argv[1]);
	const cs_mode mode = bits == 64 ? CS_MODE_64 : CS_MODE_32;
	std::ifstream in(argv[2], std::ios::binary), spans(argv[3]);
	std::ofstream rows(argv[4]);
	if (!in || !spans || !rows) return 2;
	const std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(in), {}};
	csh normal{}, fast{};
	cs_opt_mnem custom{X86_INS_UD2, "ud2"};
	if (cs_open(CS_ARCH_X86, mode, &normal) || cs_open(CS_ARCH_X86, mode, &fast) ||
	    cs_option(normal, CS_OPT_MNEMONIC, reinterpret_cast<size_t>(&custom)) ||
	    cs_option(normal, CS_OPT_DETAIL, CS_OPT_ON) || cs_option(fast, CS_OPT_DETAIL, CS_OPT_ON)) return 3;
	auto next = bits == 64 ? X86_disasmIterText : X86_disasmIter32;
	uint64_t ip;
	size_t start, n;
	std::map<std::string,Bucket> masks;
	size_t valid{}, invalid{}, misses{}, eligible{}, conflicting{}, records{};
	while (spans >> start >> n >> ip) {
		if (start > bytes.size() || n > bytes.size() - start) return 4;
		const uint8_t *p = bytes.data() + start;
		while (n) {
			cs_insn fast_record{}, ref{};
			cs_detail fast_detail{}, ref_detail{};
			fast_record.detail = &fast_detail;
			ref.detail = &ref_detail;
			const uint8_t *after = p, *observed = p;
			auto address = ip, current = ip;
			auto left = n, available = n;
			const bool accepted = cs_disasm_iter(normal, &after, &left, &address, &ref);
			census_reset();
			const bool match = next(fast, &observed, &available, &current, &fast_record);
			const int full = census_calls();
			if (match != accepted || observed != after || available != left || current != address ||
			    full > 1) return 5;
			if (accepted) {
				fast_record.detail = ref.detail;
				if (std::memcmp(&fast_record, &ref, sizeof(ref)) ||
				    std::memcmp(&fast_detail, &ref_detail, sizeof(cs_detail))) {
					std::fprintf(stderr, "record difference bitness %u IP %llx %s %s\n", bits, (unsigned long long)ip, ref.mnemonic, ref.op_str);
					return 6;
				}
				valid++; misses += full; records++;
				if(full) compare_mask(normal,fast,next,bits,p,ref,masks);
				p=after; n=left; ip=address;
			} else { ++invalid; ++p; --n; ++ip; }
		}
	}
	for(const auto &[key,b] : masks){rows<<key<<'\t'<<b.count<<'\t'<<b.first<<'\n';eligible+=b.count;}
	std::printf("%zu %zu %zu %zu %zu %zu\n",valid,invalid,misses,eligible,conflicting,records);
	cs_close(&fast);cs_close(&normal);
}
