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
struct Bucket { size_t count{}; std::string first; };

static void observe_miss(const cs_insn &insn, std::map<std::string, Bucket> &counts)
{
    const cs_x86 &x = insn.detail->x86;
    std::ostringstream shape;
    shape << insn.mnemonic << '\t';
    const bool scalar = x.opcode[0] != 0x62 && x.opcode[0] != 0xc4 && x.opcode[0] != 0xc5;
    const unsigned first = x.opcode[0], second = first == 0x0f ? x.opcode[1] : 0;
    shape << first << '/' << second << '\t';
    for (auto p : x.prefix) shape << unsigned(p) << '.';
    shape << '\t' << unsigned(x.addr_size) << '/' << (x.rex ? (x.rex & 8 ? 2 : 1) : 0) << '\t';
    if (x.encoding.modrm_offset) {
        const unsigned mr=x.modrm, mod=mr>>6, rm=mr&7;
        const char *kind=mod==3 ? "reg" : (rm==4 && x.addr_size!=2 ? "sib" : (mod==0 && rm==5 && x.addr_size!=2 ? "disp32" : "base"));
        shape << kind << '/' << unsigned(x.encoding.disp_size);
        if (scalar && (first==0x80 || first==0x81 || first==0x83 || first==0xf6 || first==0xf7 || first==0xff || first==0xc0 || first==0xc1))
            shape << '/' << ((mr>>3)&7);
    } else shape << "none";
    shape << '\t' << unsigned(x.encoding.imm_size) << '\t';
    for (unsigned i=0;i<x.op_count;i++) {
        const auto &op=x.operands[i];
        shape << unsigned(op.type) << '.' << unsigned(op.size) << '.' << unsigned(op.access) << '/';
    }
    auto &b=counts[shape.str()];
    if (!b.count) {
        static const char digits[]="0123456789abcdef";
        for (unsigned i=0;i<insn.size;i++) {const unsigned v=insn.bytes[i];b.first+=digits[v>>4];b.first+=digits[v&15];}
        b.first+='\t';b.first+=insn.op_str;
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
				if(full) observe_miss(ref,masks);
				p=after; n=left; ip=address;
			} else { ++invalid; ++p; --n; ++ip; }
		}
	}
	for(const auto &[key,b] : masks){rows<<key<<'\t'<<b.count<<'\t'<<b.first<<'\n';eligible+=b.count;}
	std::printf("%zu %zu %zu %zu %zu %zu\n",valid,invalid,misses,eligible,conflicting,records);
	cs_close(&fast);cs_close(&normal);
}
