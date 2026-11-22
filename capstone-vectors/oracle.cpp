#include <capstone/capstone.h>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstddef>
#include <sys/mman.h>
#include <unistd.h>
extern "C" bool observed_test(csh, bool, const uint8_t *, size_t, cs_insn *, uint16_t *);
int main()
{
	const size_t page = sysconf(_SC_PAGESIZE);
	auto *mem = static_cast<uint8_t *>(mmap(nullptr, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0));
	if (mem == MAP_FAILED || mprotect(mem + page, page, PROT_NONE)) return 1;
	uint64_t trials = 0, hits[2]{};
	for (bool wide : {false, true}) for (bool detail : {false, true}) {
		csh fast, canonical;
		cs_opt_mnem name{X86_INS_UD2,"ud2"};
		if (cs_open(CS_ARCH_X86, wide ? CS_MODE_64 : CS_MODE_32, &fast) ||
		    cs_open(CS_ARCH_X86, wide ? CS_MODE_64 : CS_MODE_32, &canonical) ||
		    cs_option(canonical, CS_OPT_MNEMONIC, reinterpret_cast<size_t>(&name))) return 1;
		if (detail && (cs_option(fast, CS_OPT_DETAIL, CS_OPT_ON) ||
			       cs_option(canonical, CS_OPT_DETAIL, CS_OPT_ON))) return 1;
		auto check = [&](const uint8_t *bytes, unsigned n, unsigned length, bool permitted) {
			auto *p = mem + page - n;
			std::memcpy(p, bytes, n);
			cs_insn actual, expected;
			cs_detail a, b;
			std::memset(&actual, 0xa5, sizeof(actual));
			std::memset(&a, 0xa5, sizeof(a));
			std::memcpy(&expected, &actual, sizeof(actual));
			std::memcpy(&b, &a, sizeof(a));
			actual.detail = detail ? &a : nullptr;
			expected.detail = detail ? &b : nullptr;
			actual.address = expected.address = UINT32_MAX;
			uint16_t out = 0xffcc;
			++trials;
			if (!observed_test(fast, wide, p, n, &actual, &out)) {
				actual.detail = expected.detail;
				return out == 0xffcc && !std::memcmp(&actual, &expected, sizeof(actual)) &&
				       !std::memcmp(&a, &b, sizeof(a));
			}
			const uint8_t *cur = p;
			size_t left = n;
			uint64_t ip = actual.address;
			if (!permitted || !cs_disasm_iter(canonical, &cur, &left, &ip, &expected) ||
			    cur != p + length || left != n - length || ip != actual.address + length ||
			    out != length || actual.size != length || actual.id != X86_INS_TEST ||
			    std::memcmp(&a, &b, offsetof(cs_detail, x86) + sizeof(cs_x86))) return false;
			actual.detail = expected.detail;
			if (std::memcmp(&actual, &expected, sizeof(actual))) return false;
			++hits[wide];
			return true;
		};
		const uint32_t values[] = {0,1,9,10,127,128,255,0x12345678,0x80000000,0xFFFFFFFF};
		for (unsigned mr = 0; mr < 256; ++mr) {
			unsigned mod = mr >> 6, rm = mr & 7;
			bool sib = rm == 4 && mod != 3;
			for (unsigned sb = 0; sb < (sib ? 256u : 1u); ++sb) {
				unsigned offset = 2 + sib;
				unsigned disp = mod == 1 ? 1 : mod == 2 || (!mod && (rm == 5 || (sib && (sb & 7) == 5))) ? 4 : 0;
				unsigned length = offset + disp + 1;
				for (auto value : values) {
					std::array<uint8_t, 12> bytes{0xf6, (uint8_t)mr, (uint8_t)sb};
					for (unsigned j = 0; j < disp; ++j) bytes[offset+j] = (uint8_t)(value >> (8*j));
					bytes[offset+disp] = (uint8_t)value;
					bool permitted = !wide && mr < 192 && !(mr & 0x38);
					if (!check(bytes.data(), length, length, permitted)) {
						std::fprintf(stderr, "full %u %u %#x %#x %#x\n",wide,detail,mr,sb,value);return 2;
					}
					if (value == 0) for (unsigned n = 0; n < length; ++n)
						if (!check(bytes.data(), n, length, false)) return 3;
				}
			}
		}
		for (unsigned imm=0;imm<256;++imm) {
			const uint8_t bytes[] = {0xf6,0x00,(uint8_t)imm,0x90};
			if (!check(bytes,sizeof(bytes),3,!wide)) return 4;
		}
		if (cs_option(fast, CS_OPT_MNEMONIC, reinterpret_cast<size_t>(&name))) return 1;
		const uint8_t sample[] = {0xf6,0x00,1};
		if (!check(sample,3,3,false)) return 5;
		cs_close(&fast);cs_close(&canonical);
	}
	munmap(mem,page*2);
	std::printf("%llu %llu %llu\n",(unsigned long long)trials,(unsigned long long)hits[0],(unsigned long long)hits[1]);
}
