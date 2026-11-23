#include "arch/X86/X86ScanAdapter.h"
#include <algorithm>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <vector>

static size_t skip(const uint8_t *, size_t size, size_t offset, void *context) {
    auto *calls = static_cast<unsigned *>(context);
    ++*calls;
    return size - offset;
}
struct Handles {
    csh iter = 0, single = 0;
    Handles(cs_mode mode) {
        if (cs_open(CS_ARCH_X86, mode, &iter) || cs_open(CS_ARCH_X86, mode, &single)) std::abort();
    }
    ~Handles() { cs_close(&iter); cs_close(&single); }
    void option(cs_opt_type option, size_t value) {
        if (cs_option(iter, option, value) || cs_option(single, option, value)) std::abort();
    }
};
static size_t check(Handles &h, const uint8_t *data, size_t length, uint64_t ip,
                    unsigned fill, bool allocate_detail) {
    cs_detail details[2];
    cs_insn a[2];
    std::memset(details, fill, sizeof(details));
    std::memset(a, fill, sizeof(a));
    for (unsigned i = 0; i < 2; ++i) {
        a[i].is_alias = a[i].usesAliasDetails = a[i].illegal = false;
        a[i].detail = allocate_detail ? details + i : nullptr;
    }
    const uint8_t *cursor = data;
    size_t left = length;
    uint64_t address = ip;
    const bool ok = X86_disasmIterText(h.iter, &cursor, &left, &address, &a[0]);
    const bool got = X86_decodeOneText(h.single, data, length, ip, &a[1]);
    const size_t used = length-left;
    bool same = ok == got && left + used == length && cursor == data + used &&
                address == ip + used && cs_errno(h.iter) == cs_errno(h.single);
    for (unsigned i = 0; i < 2; ++i) {
        same &= a[i].detail == (allocate_detail ? details + i : nullptr);
        a[i].detail = nullptr;
    }
    if (!same || std::memcmp(a, a + 1, sizeof(cs_insn)) || std::memcmp(details, details + 1, sizeof(cs_detail))) {
        std::fprintf(stderr, "single-record mismatch at %" PRIx64 " size=%zu got=%zu old=%zu id=%u/%u\n",
                     ip, length, used, length - left, a[0].id, a[1].id);
        std::exit(2);
    }
    return used;
}
int main(int argc, char **argv) {
    if (argc != 3) return 1;
    const int bits = std::atoi(argv[1]);
    const auto mode = bits == 16 ? CS_MODE_16 : bits == 32 ? CS_MODE_32 : CS_MODE_64;
    Handles h(mode);
    std::ifstream stream(argv[2], std::ios::binary);
    std::vector<uint8_t> input{std::istreambuf_iterator<char>(stream), {}};
    if (input.empty()) return 1;
    uint64_t attempts = 0;
    const uint8_t invalid[] = {0x0f};
    cs_insn z{};
    if (X86_decodeOneText(0, invalid, 1, 0, &z) || X86_decodeOneText(h.single, invalid, 0, 0, &z)) return 2;
    for (unsigned cfg = 0; cfg < 8; ++cfg) {
        bool detail = (cfg & 1) != 0;
        h.option(CS_OPT_DETAIL, detail ? CS_OPT_ON : CS_OPT_OFF);
        h.option(CS_OPT_TEXT, cfg == 4 || cfg == 5 ? CS_OPT_OFF : CS_OPT_ON);
        h.option(CS_OPT_SKIPDATA, cfg >= 6 ? CS_OPT_ON : CS_OPT_OFF);
        if (!cs_support(CS_SUPPORT_DIET)) {
            h.option(CS_OPT_SYNTAX, cfg == 2 || cfg == 3 ? CS_OPT_SYNTAX_ATT : CS_OPT_SYNTAX_INTEL);
            cs_opt_mnem custom = {X86_INS_MOV, cfg == 6 ? "alternate" : nullptr};
            h.option(CS_OPT_MNEMONIC, reinterpret_cast<size_t>(&custom));
        }
        for (size_t i = 0; i < input.size();) {
            const size_t used = check(h, input.data() + i, input.size() - i,
                                      UINT64_MAX - 0x10000 + i, (i & 1) ? 0xa5 : 0, detail || (cfg & 2));
            i += used ? used : 1;
            ++attempts;
        }
        for (size_t tail = 0; tail < 16; ++tail) {
            const size_t n = std::min(tail, input.size());
            check(h, input.data() + input.size() - n, n, UINT64_MAX - n / 2, 0x5a, detail);
        }
    }
    std::vector<uint8_t> padding(70000, 0x66);
    unsigned visits[2]{};
    cs_opt_skipdata sd[]{ {".blob", skip, &visits[0]}, {".blob", skip, &visits[1]} };
    if (cs_option(h.iter, CS_OPT_SKIPDATA_SETUP, reinterpret_cast<size_t>(sd)) ||
        cs_option(h.single, CS_OPT_SKIPDATA_SETUP, reinterpret_cast<size_t>(sd + 1))) return 2;
    h.option(CS_OPT_DETAIL, CS_OPT_OFF); h.option(CS_OPT_SKIPDATA, CS_OPT_ON);
    if (check(h, padding.data(), padding.size(), 11, 0, false) != padding.size() ||
        visits[0] != 1 || visits[1] != 1) return 2;
    std::printf("{\"records\":%" PRIu64 ",\"tails\":128,\"callback_bytes\":%zu}\n", attempts, padding.size());
}
