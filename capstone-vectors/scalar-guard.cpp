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

extern "C" bool observed_plain(csh, bool, const uint8_t *, size_t,
                               cs_insn *, uint16_t *);

int main(int argc, char **) {
    bool candidate = argc == 2;
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
        auto check = [&](const std::array<uint8_t, 18>& bytes, unsigned n,
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
            if (!observed_plain(fast, wide, p, n, &actual, &length)) {
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
                length < 3 || length > n || cursor != p + length || left != n - length ||
                ip != actual.address + length || actual.id != reference.id ||
                actual.size != length || reference.size != length ||
                std::memcmp(actual.bytes, reference.bytes, sizeof(actual.bytes)) ||
                std::memcmp(actual.mnemonic, reference.mnemonic, sizeof(actual.mnemonic)) ||
                std::memcmp(actual.op_str, reference.op_str, sizeof(actual.op_str)) ||
                (detail && std::memcmp(&act, &ref, offsetof(cs_detail, x86) + sizeof(cs_x86))))
                { std::fprintf(stderr,"mismatch %s | %s  /  %s | %s\n",actual.mnemonic,actual.op_str,reference.mnemonic,reference.op_str); return false; }
            actual.detail = reference.detail;
            if (std::memcmp(&actual, &reference, sizeof(actual)) ||
                std::memcmp(&act, &ref, sizeof(act))) return false;
            return true;
        };
        for (unsigned pfx=1;pfx<=8;++pfx) for (unsigned seg=0;seg<=1;++seg) {
            std::array<uint8_t,18> body{};
            std::memset(body.data(),0x66,pfx);
            if (seg) body[pfx]=0x2e;
            const unsigned lead=pfx+seg, length=lead+8;
            body[lead]=0x0f; body[lead+1]=0x1f; body[lead+2]=0x84;
            for (unsigned n=0;n<=body.size();++n) {
                const bool eligible=wide && lead>=2 && n>=length && length<=15;
                uint64_t prior=hits64;
                if (!check(body,n,!eligible) || ((hits64!=prior)!=(eligible && candidate))) {
                    std::fprintf(stderr,"prefix %u cs %u n %u candidate %u expected %u\\n",pfx,seg,n,candidate,eligible);
                    return 3;
                }
            }
            for (unsigned byte=0;byte<length;++byte) for(unsigned v=0;v<256;++v) {
                auto changed=body;changed[byte]=uint8_t(v);
                for(unsigned n=0;n<=length;++n)
                    if(!check(changed,n,false)) {
                        std::fprintf(stderr,"mutation pfx %u cs %u byte %u value %u n %u\\n",pfx,seg,byte,v,n);
                        return 4;
                    }
            }
        }
        std::array<uint8_t,18> prefixed{0x66,0x2e,0x0f,0x1f,0x84};
        if(cs_option(fast,CS_OPT_MNEMONIC,reinterpret_cast<size_t>(&names)) || !check(prefixed,10,true))return 6;
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
