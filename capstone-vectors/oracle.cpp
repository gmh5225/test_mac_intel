#include <capstone/capstone.h>
#include <array>
#include <cstddef>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

extern "C" bool observed_legacy(csh, bool, const uint8_t *, size_t,
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
            if (!observed_legacy(fast, wide, p, n, &actual, &length)) {
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
                length != 5 + ((bytes[1] & 0xf0) == 0x40) || cursor != p + length || left != n - length ||
                ip != actual.address + length || actual.id != reference.id ||
                actual.size != length || reference.size != length ||
                std::memcmp(actual.bytes, reference.bytes, sizeof(actual.bytes)) ||
                std::memcmp(actual.mnemonic, reference.mnemonic, sizeof(actual.mnemonic)) ||
                std::memcmp(actual.op_str, reference.op_str, sizeof(actual.op_str)) ||
                (detail && std::memcmp(&act, &ref, offsetof(cs_detail, x86) + sizeof(cs_x86))))
                return false;
            return true;
        };
        for (unsigned prefix=0;prefix<=16;++prefix) for(unsigned opcode=0x6f;opcode<=0x74;++opcode)
            for(unsigned mr=0;mr<=255;++mr) for(unsigned value=0;value<256;++value) {
                if ((mr<192 || !wide || opcode<0x70 || opcode>0x73) && value%43) continue;
                std::array<uint8_t,7> bytes{{0x66,static_cast<uint8_t>(0x3f+prefix),0x0f,
                    static_cast<uint8_t>(opcode),static_cast<uint8_t>(mr),static_cast<uint8_t>(value),0}};
                const unsigned n=5+(prefix!=0);
                if (!prefix) std::memmove(bytes.data()+1,bytes.data()+2,4);
                if (!check(bytes,n,!wide || mr<192 || opcode<0x70 || opcode>0x73)) {
                    std::fprintf(stderr,"mismatch prefix=%u op=%x mr=%x imm=%x\\n",prefix,opcode,mr,value);return 3;
                }
                if ((value & 31)==0) for(unsigned end=0;end<n;++end)
                    if (!check(bytes,end,true)) return 4;
            }
        std::array<uint8_t,7> supported{{0x66,0x44,0x0f,0x70,0xdc,0xe4,0}};
        if (cs_option(fast,CS_OPT_MNEMONIC,reinterpret_cast<size_t>(&names)) ||
            !check(supported,6,true)) return 5;
        cs_close(&ordinary);
        cs_close(&fast);
    }
    munmap(area, page*2);
    std::printf("%llu %llu %llu\n", (unsigned long long)trials,
                (unsigned long long)hits32,(unsigned long long)hits64);
}
