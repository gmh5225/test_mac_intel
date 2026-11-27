#include <capstone/capstone.h>
#include <array>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <vector>

extern "C" bool observed_plain(csh, bool, const uint8_t *, size_t, cs_insn *, uint16_t *);

int main(int argc, char **argv)
{
    if (argc != 4) return 1;
    std::ifstream file(argv[1], std::ios::binary), extents(argv[2]);
    std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(file), {}};
    const bool wide = std::atoi(argv[3]) == 64;
    const cs_mode mode = wide ? CS_MODE_64 : CS_MODE_32;
    csh ordinary = 0, fast = 0;
    if (bytes.empty() || !extents || cs_open(CS_ARCH_X86, mode, &ordinary) || cs_open(CS_ARCH_X86, mode, &fast)) return 2;
    cs_opt_mnem custom{X86_INS_UD2, "ud2"};
    if (cs_option(ordinary, CS_OPT_MNEMONIC, reinterpret_cast<size_t>(&custom))) return 3;
    cs_insn *record=cs_malloc(ordinary);
    if (!record) return 4;
    uint64_t total=0, rejected=0, offset, count, ip;
    std::array<uint64_t,3> shapes{}, longest{};
    while (extents >> offset >> count >> ip) {
        if (offset>bytes.size() || count>bytes.size()-offset) return 5;
        const uint8_t *p=bytes.data()+offset;
        size_t size=count;
        while (size) {
            const uint8_t *start=p;
            const size_t available=size;
            if (!cs_disasm_iter(ordinary,&p,&size,&ip,record)) {
                ++p; --size; ++ip; ++rejected;
                continue;
            }
            ++total;
            if (!wide || record->id!=X86_INS_VMOVDQU8) continue;
            cs_insn out{};
            out.address=record->address;
            uint16_t length=0;
            if (!observed_plain(fast,wide,start,available,&out,&length)) continue;
            if (length!=p-start || std::strcmp(out.op_str,record->op_str) || std::strcmp(out.mnemonic,record->mnemonic)) return 6;
            const unsigned which=start[5]>=0xc0 ? 0 : start[4]==0x7f ? 1 : 2;
            const char *comma=std::strchr(out.op_str,',');
            if (!comma) return 7;
            const size_t used=std::strlen(comma)+1;
            if (used > (which==2 ? sizeof(", zmmword ptr [r15 + r15*8 - 0x80000000]") : sizeof(", zmm31"))) return 8;
            ++shapes[which]; longest[which]=std::max<uint64_t>(longest[which],used);
        }
    }
    if (!extents.eof() || !total) return 9;
    cs_free(record,1); cs_close(&ordinary); cs_close(&fast);
    std::printf("%llu %llu",static_cast<unsigned long long>(total),static_cast<unsigned long long>(rejected));
    for (auto n : shapes) std::printf(" %llu",static_cast<unsigned long long>(n));
    for (auto n : longest) std::printf(" %llu",static_cast<unsigned long long>(n));
    std::puts("");
}
