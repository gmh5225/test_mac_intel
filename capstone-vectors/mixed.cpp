#include <capstone/capstone.h>
#include <array>
#include <cstddef>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

extern "C" bool observed_mixed(csh, bool, const uint8_t *, size_t,
                               cs_insn *, uint16_t *);

int main() {
    uint64_t trials = 0, hits32 = 0, hits64 = 0;
    const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    auto *area = static_cast<uint8_t *>(mmap(nullptr, page * 2,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0));
    if (area == MAP_FAILED || mprotect(area + page, page, PROT_NONE))
        return 2;
    for (unsigned wide : {0, 1}) for (unsigned detail : {0, 1}) {
        const auto mode = wide ? CS_MODE_64 : CS_MODE_32;
        csh fast = 0, ordinary = 0;
        cs_opt_mnem names{X86_INS_UD2, "ud2"};
        if (cs_open(CS_ARCH_X86, mode, &fast) || cs_open(CS_ARCH_X86, mode, &ordinary) ||
            cs_option(ordinary, CS_OPT_MNEMONIC, reinterpret_cast<size_t>(&names)))
            return 1;
        if (detail && (cs_option(fast, CS_OPT_DETAIL, CS_OPT_ON) ||
                       cs_option(ordinary, CS_OPT_DETAIL, CS_OPT_ON))) return 1;
        auto check = [&](const std::array<uint8_t, 7>& bytes, unsigned n,
                         bool must_reject) {
            auto *p = area + page - n;
            std::memcpy(p, bytes.data(), n);
            cs_insn actual, reference;
            cs_detail act, ref;
            std::memset(&actual, 0xa5, sizeof(actual));
            std::memset(&act, 0xa5, sizeof(act));
            std::memcpy(&reference, &actual, sizeof(actual));
            std::memcpy(&ref, &act, sizeof(ref));
            actual.detail = detail ? &act : nullptr;
            reference.detail = detail ? &ref : nullptr;
            actual.address = reference.address = 0x31415926;
            uint16_t length = 0xeeff;
            ++trials;
            if (!observed_mixed(fast, wide, p, n, &actual, &length)) {
                actual.detail = reference.detail;
                if (length != 0xeeff || std::memcmp(&actual, &reference, sizeof(actual)) ||
                    std::memcmp(&act, &ref, sizeof(act))) return false;
                return true;
            }
            if (must_reject) return false;
            (wide ? hits64 : hits32)++;
            const uint8_t *cursor = p;
            size_t left = n;
            uint64_t ip = reference.address;
            if (!cs_disasm_iter(ordinary, &cursor, &left, &ip, &reference) ||
                length != 6 || cursor != p + length || left != n - length ||
                ip != actual.address + length || actual.id != reference.id ||
                actual.size != length || reference.size != length ||
                std::memcmp(actual.bytes, reference.bytes, sizeof(actual.bytes)) ||
                std::memcmp(actual.mnemonic, reference.mnemonic, sizeof(actual.mnemonic)) ||
                std::memcmp(actual.op_str, reference.op_str, sizeof(actual.op_str)) ||
                (detail && std::memcmp(&act, &ref, offsetof(cs_detail, x86) + sizeof(cs_x86))))
                return false;
            return true;
        };
        constexpr unsigned opcodes[] = {0, 1, 2, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x37, 0x38, 0x39, 0x3a, 0xef, 0xf0, 0xf1};
        for (auto op : opcodes) for (unsigned flags=0; flags<256; ++flags)
            for (unsigned ext=0; ext<8; ++ext) for(unsigned regs=0; regs<8; ++regs) {
                const auto mr = static_cast<uint8_t>((regs < 2 ? regs*64 : 192) |
                    (((flags + regs) & 7) << 3) | ((regs ^ ext) & 7));
                std::array<uint8_t,7> bytes{{0xc4,static_cast<uint8_t>((ext<<5)|3),
                    static_cast<uint8_t>(flags),static_cast<uint8_t>(op),mr,
                    static_cast<uint8_t>(op + ext*43 + flags*17 + regs),0}};
                for (unsigned n=0; n<=7; ++n) if (!check(bytes,n,n<6)) {
                    std::fprintf(stderr, "VEX mismatch wide=%u detail=%u op=%02x P0=%02x P1=%02x ModRM=%02x length=%u\n",wide,detail,op,bytes[1],flags,mr,n);
                    return 3;
                }
            }
        std::array<uint8_t,7> supported{{0xc4,0xe3,0x7d,0x18,0xd1,0x7f,0}};
        for (unsigned map = 0; map < 32; ++map) {
            if (map == 3) continue;
            auto bytes=supported; bytes[1]=static_cast<uint8_t>(0xe0|map);
            if (!check(bytes,6,true)) return 4;
        }
        if (cs_option(fast,CS_OPT_MNEMONIC,reinterpret_cast<size_t>(&names)) ||
            !check(supported,6,true)) return 5;
        cs_close(&ordinary);
        cs_close(&fast);
    }
    munmap(area, page*2);
    std::printf("%llu %llu %llu\n", (unsigned long long)trials,
                (unsigned long long)hits32,(unsigned long long)hits64);
}
