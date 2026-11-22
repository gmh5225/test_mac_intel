#include <capstone/capstone.h>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>

extern "C" bool observed_sib(csh, const uint8_t *, size_t, cs_insn *, uint16_t *);

int main(int argc, char **argv)
{
    if (argc != 3)
        return 1;
    std::ifstream file(argv[1], std::ios::binary), spans(argv[2]);
    if (!file || !spans)
        return 2;
    std::vector<uint8_t> data{std::istreambuf_iterator<char>(file), {}};
    csh fast = 0, canonical = 0;
    cs_opt_mnem neutral{X86_INS_UD2, "ud2"};
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &fast) ||
        cs_open(CS_ARCH_X86, CS_MODE_32, &canonical) ||
        cs_option(canonical, CS_OPT_MNEMONIC, reinterpret_cast<size_t>(&neutral)))
        return 3;
    auto *ref = cs_malloc(canonical);
    if (!ref)
        return 4;
    size_t begin, length, total = 0, hits = 0, lea = 0;
    uint64_t address;
    while (spans >> begin >> length >> address) {
        if (begin > data.size() || length > data.size() - begin)
            return 5;
        const auto *p = data.data() + begin;
        while (length) {
            const auto *at = p;
            const auto left = length;
            const auto ip = address;
            if (!cs_disasm_iter(canonical, &p, &length, &address, ref)) {
                ++p;
                --length;
                ++address;
                continue;
            }
            cs_insn rec{};
            rec.address = ip;
            uint16_t size = 0;
            ++total;
            if (observed_sib(fast, at, left, &rec, &size)) {
                if (size != ref->size || rec.id != ref->id)
                    return 6;
                ++hits;
                lea += ref->id == X86_INS_LEA;
            }
        }
    }
    cs_free(ref, 1);
    cs_close(&fast);
    cs_close(&canonical);
    std::cout << total << ' ' << hits << ' ' << lea << '\n';
    return total ? 0 : 7;
}
