#include <capstone/capstone.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <vector>

int main(int argc, char **argv) {
    if (argc != 4) return 1;
    const unsigned bits = std::strtoul(argv[1], nullptr, 10);
    csh handle = 0;
    if (cs_open(CS_ARCH_X86, bits == 64 ? CS_MODE_64 : CS_MODE_32, &handle) ||
        cs_option(handle, CS_OPT_TEXT, CS_OPT_OFF)) return 2;
    cs_insn *insn = cs_malloc(handle);
    if (!insn) return 2;
    std::ifstream input(argv[2], std::ios::binary), spans(argv[3]);
    if (!input || !spans) return 3;
    const std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(input), {}};
    uint64_t decoded = 0, invalid = 0, c5 = 0, c4 = 0, evex = 0;
    size_t start, left;
    uint64_t address;
    while (spans >> start >> left >> address) {
        if (start > bytes.size() || left > bytes.size() - start) return 3;
        const uint8_t *cursor = bytes.data() + start;
        while (left) {
            const uint8_t *begin = cursor;
            if (!cs_disasm_iter(handle, &cursor, &left, &address, insn)) {
                ++invalid; ++cursor; --left; ++address;
                continue;
            }
            ++decoded;
            if (begin[0] == 0xc5 && insn->id != X86_INS_LDS) ++c5;
            else if (begin[0] == 0xc4 && insn->id != X86_INS_LES) ++c4;
            else if (begin[0] == 0x62 && insn->id != X86_INS_BOUND) ++evex;
        }
    }
    cs_free(insn, 1);
    cs_close(&handle);
    std::printf("{\"decoded\":%llu,\"invalid_bytes\":%llu,\"bare_c5\":%llu,\"bare_c4\":%llu,\"bare_62\":%llu}\n",
                (unsigned long long)decoded, (unsigned long long)invalid,
                (unsigned long long)c5, (unsigned long long)c4,
                (unsigned long long)evex);
}
