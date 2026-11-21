#include <capstone/capstone.h>
#include "arch/X86/X86ScanAdapter.h"
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

static uint64_t next_word = UINT64_C(0x8912208b1440123);
static uint64_t random_word()
{
    next_word ^= next_word << 13;
    next_word ^= next_word >> 7;
    return next_word ^= next_word << 17;
}

int main()
{
    std::vector<uint64_t> targets{0, 1, 8, 9, 10, 15, 16, UINT64_MAX};
    for (unsigned shift = 4; shift < 64; shift += 4) {
        uint64_t place = UINT64_C(1) << shift;
        for (unsigned digit = 1; digit < 16; ++digit) {
            targets.push_back(place * digit - 1);
            targets.push_back(place * digit);
            targets.push_back(place * digit + 1);
        }
    }
    for (unsigned i = 0; i < 2048; ++i)
        targets.push_back(random_word());
    size_t comparisons = 0;
    for (auto mode : {CS_MODE_32, CS_MODE_64}) {
        csh handle;
        if (cs_open(CS_ARCH_X86, mode, &handle) != CS_ERR_OK)
            return 1;
        for (bool detail : {false, true}) {
            cs_option(handle, CS_OPT_DETAIL, detail ? CS_OPT_ON : CS_OPT_OFF);
            for (unsigned op = 0; op < 35; ++op) {
                const bool two_byte = op >= 19;
                const bool rel8 = op == 2 || (op >= 3 && op < 19);
                const unsigned immediate = rel8 ? 1 : 4;
                const unsigned prefix = two_byte ? 2 : 1;
                const unsigned length = prefix + immediate;
                uint8_t code[6]{};
                code[0] = op == 0 ? 0xe8 : op == 1 ? 0xe9 : op == 2 ? 0xeb :
                          two_byte ? 0x0f : 0x70 + op - 3;
                if (two_byte)
                    code[1] = 0x80 + op - 19;
                for (uint64_t requested : targets) {
                    uint32_t encoded = uint32_t(random_word());
                    for (unsigned b = 0; b < immediate; ++b)
                        code[prefix + b] = uint8_t(encoded >> (8 * b));
                    int64_t disp = rel8 ? int64_t(int8_t(encoded)) :
                                         int64_t(int32_t(encoded));
                    uint64_t target = mode == CS_MODE_32 ? uint32_t(requested) : requested;
                    uint64_t pc[2] = {requested - length - uint64_t(disp), 0};
                    pc[1] = pc[0];
                    size_t left[2] = {length, length};
                    const uint8_t *cursor[2] = {code, code};
                    cs_insn a[2]; cs_detail d[2];
                    const auto fill = int(next_word & 255);
                    std::memset(a, fill, sizeof(a)); std::memset(d, fill, sizeof(d));
                    for (unsigned i = 0; i < 2; ++i) {
                        a[i].illegal = a[i].is_alias = a[i].usesAliasDetails = false;
                        a[i].detail = detail ? &d[i] : nullptr;
                    }
                    char expected[24];
                    std::snprintf(expected, sizeof(expected), target > 9 ? "0x%" PRIx64 : "%" PRIu64, target);
                    if (!cs_disasm_iter(handle, &cursor[0], &left[0], &pc[0], &a[0]) ||
                        !(mode == CS_MODE_32 ? X86_disasmIter32 : X86_disasmIterText)(handle, &cursor[1], &left[1], &pc[1], &a[1]))
                        return 2;
                    if (a[0].detail != (detail ? &d[0] : nullptr) ||
                        a[1].detail != (detail ? &d[1] : nullptr))
                        return 3;
                    a[0].detail = a[1].detail = nullptr;
                    if (std::strcmp(a[1].op_str, expected) || left[0] || left[1] ||
                        pc[0] != pc[1] || cursor[0] != cursor[1] ||
                        std::memcmp(&a[0], &a[1], sizeof(a[0])) ||
                        std::memcmp(&d[0], &d[1], sizeof(d[0]))) {
                        std::fprintf(stderr, "mode %u detail %u opcode %u target %s public %s private %s\n",
                                     unsigned(mode), unsigned(detail), op, expected, a[0].op_str, a[1].op_str);
                        return 4;
                    }
                    ++comparisons;
                }
            }
        }
        cs_close(&handle);
    }
    std::printf("%zu complete public/private records and independent target strings agree\n", comparisons);
}
