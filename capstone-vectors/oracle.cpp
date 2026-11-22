#include <capstone/capstone.h>
#include <array>
#include <cstddef>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

extern "C" bool observed_broadcast(csh, bool, const uint8_t *, size_t,
                               cs_insn *, uint16_t *);

int main() {
    uint64_t trials = 0, hits32 = 0, hits64 = 0;
#ifdef _WIN32
    SYSTEM_INFO system;
    GetSystemInfo(&system);
    const size_t page = system.dwPageSize;
    auto *area = static_cast<uint8_t *>(VirtualAlloc(nullptr, page * 2, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    DWORD old_flags;
    if (!area || !VirtualProtect(area + page, page, PAGE_NOACCESS, &old_flags))
        return 2;
#else
    const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    auto *area = static_cast<uint8_t *>(mmap(nullptr, page * 2,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0));
    if (area == MAP_FAILED || mprotect(area + page, page, PROT_NONE))
        return 2;
#endif
    for (unsigned wide : {0, 1}) for (unsigned detail : {0, 1}) {
        const auto mode = wide ? CS_MODE_64 : CS_MODE_32;
        csh fast = 0, ordinary = 0;
        cs_opt_mnem names{X86_INS_UD2, "ud2"};
        if (cs_open(CS_ARCH_X86, mode, &fast) || cs_open(CS_ARCH_X86, mode, &ordinary) ||
            cs_option(ordinary, CS_OPT_MNEMONIC, reinterpret_cast<size_t>(&names)))
            return 1;
        if (detail && (cs_option(fast, CS_OPT_DETAIL, CS_OPT_ON) ||
                       cs_option(ordinary, CS_OPT_DETAIL, CS_OPT_ON))) return 1;
        auto check = [&](const auto &bytes, unsigned n,
                         bool must_reject) {
            auto *p = area + page - n;
            if (n > sizeof(bytes)) return false;
            std::memcpy(p, bytes, n);
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
            if (!observed_broadcast(fast, wide, p, n, &actual, &length)) {
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
                (length < 6 || length > 8) || length > n || cursor != p + length || left != n - length ||
                ip != actual.address + length || actual.id != reference.id ||
                actual.size != length || reference.size != length ||
                std::memcmp(actual.bytes, reference.bytes, sizeof(actual.bytes)) ||
                std::memcmp(actual.mnemonic, reference.mnemonic, sizeof(actual.mnemonic)) ||
                std::memcmp(actual.op_str, reference.op_str, sizeof(actual.op_str)) ||
                (detail && std::memcmp(&act, &ref, offsetof(cs_detail, x86) + sizeof(cs_x86))))
                return false;
            actual.detail = reference.detail;
            if (std::memcmp(&actual, &reference, sizeof(actual)) ||
                std::memcmp(&act, &ref, sizeof(act))) return false;
            return true;
        };
        for (unsigned opcode : {0x1au, 0x5au}) {
            for (unsigned ext = 0; ext < 16; ++ext)
                for (unsigned w = 0; w < 2; ++w)
                    for (unsigned ll = 0; ll < 4; ++ll)
                        for (unsigned mr = 0; mr < 256; ++mr) {
                            bool sib = (mr & 7) == 4 && mr < 0xc0;
                            for (unsigned disp : {0u, 1u, 9u, 15u, 16u, 127u, 128u, 255u}) {
                                uint8_t code[] = {0x62, uint8_t(2 | ext << 4), uint8_t(0x7d | w << 7),
                                                  uint8_t(8 | ll << 5), uint8_t(opcode), uint8_t(mr),
                                                  0x24, 0, 0x23, 0x45, 0x67, 0x89};
                                code[6 + sib] = uint8_t(disp);
                                bool reject = !wide || ll == 3 || mr >= 0x80 || (mr < 0x40 && (mr & 7)==5) ||
                                              (sib && !(ext & 4));
                                if (!check(code, sizeof(code), reject) ||
                                    !check(code, (ext + mr + w + ll + disp) % 10, reject)) return 3;
                            }
                        }
            for (unsigned field = 0; field <= 7; ++field)
                for (unsigned value = 0; value < 256; ++value)
                    for (unsigned n = 0; n <= 9; ++n) {
                        uint8_t code[] = {0x62, 0xf2, 0x7d, 0x48, uint8_t(opcode), 0x44, 0x24, 0x80, 0};
                        code[field] = uint8_t(value);
                        if (!check(code, n, !wide)) return 4;
                    }
        }
        const uint8_t supported[] = {0x62,0xf2,0x7d,0x48,0x5a,0x41,1};
        if (cs_option(fast, CS_OPT_UNSIGNED, CS_OPT_ON) || !check(supported, 7, true) ||
            cs_option(fast, CS_OPT_UNSIGNED, CS_OPT_OFF) ||
            cs_option(fast, CS_OPT_MNEMONIC, reinterpret_cast<size_t>(&names)) ||
            !check(supported, 7, true)) return 5;
        cs_close(&ordinary);
        cs_close(&fast);
    }
#ifdef _WIN32
    VirtualFree(area,0,MEM_RELEASE);
#else
    munmap(area,page*2);
#endif
    std::printf("%llu %llu %llu\n", (unsigned long long)trials,
                (unsigned long long)hits32,(unsigned long long)hits64);
}
