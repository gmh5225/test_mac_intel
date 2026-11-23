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
				if (full) {
                    const cs_x86 &x=ref.detail->x86;
                    bool sib=x.encoding.modrm_offset && x.addr_size!=2 && (x.modrm & 7)==4 && x.modrm<0xc0;
                    rows<<records<<' '<<(p-bytes.data())<<' '<<ref.size<<' '<<unsigned(x.modrm)<<' '<<(sib?int(x.sib):-1)<<' '<<ref.mnemonic<<'\n';
                    ++eligible;
                }
				p=after; n=left; ip=address;
			} else { ++invalid; ++p; --n; ++ip; }
		}
	}
	std::printf("%zu %zu %zu %zu %zu %zu\n",valid,invalid,misses,eligible,conflicting,records);
	cs_close(&fast);cs_close(&normal);
}
