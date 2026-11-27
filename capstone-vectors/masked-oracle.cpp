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
        auto check = [&](const std::array<uint8_t, 11>& bytes, unsigned n,
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
                length < 6 || length > n || cursor != p + length || left != n - length ||
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
// Sweep the register-extension bits, every mask/width and ModR/M,
        // plus truncations, invalid EVEX fields and all scales on indexed memory.
        for (unsigned ext=0;ext<16;++ext) for(unsigned ll=0;ll<4;++ll)
            for(unsigned mask=0;mask<8;++mask) for(unsigned zero:{0u,1u})
            for(unsigned op:{0x6fu,0x7fu}) for(unsigned mr=0;mr<256;++mr) {
                std::array<uint8_t,11>b{0x62,uint8_t((ext<<4)|1),0x7f,
                    uint8_t((zero<<7)|(ll<<5)|8|mask),uint8_t(op),uint8_t(mr),
                    uint8_t((mr*3+ext*17+mask)&255),0x81,0xef,0xfe,0x80};
                const bool reject=!wide || !mask ||ll==3 || (op==0x7f && ((mr>>6)==3||zero));
                if(!check(b,11,reject)){std::fprintf(stderr,"ext=%x ll=%u mask=%u z=%u op=%x mr=%x sib=%x\n",ext,ll,mask,zero,op,mr,b[6]);return 3;}
                if((mr&0x38)==0 && ext==0)for(unsigned n=0;n<11;++n)
                    if(!check(b,n,reject||n<6)){std::fprintf(stderr,"trunc %u mr %x\n",n,mr);return 4;}
            }
        for(unsigned idx=0;idx<6;++idx)for(unsigned v=0;v<256;++v)for(unsigned sib=0;sib<256;sib+=3){
            std::array<uint8_t,11>b{0x62,0xf1,0x7f,0x49,0x6f,0x44,uint8_t(sib),0x80,0,0,0};
            b[idx]=uint8_t(v);if(!check(b,11,!wide)){std::fprintf(stderr,"field %u value %x sib %x\n",idx,v,sib);return 5;}
        }
        for (unsigned ext : {0x01u,0x11u,0x91u,0xf1u})
            for (unsigned op : {0x6fu,0x7fu}) for (unsigned mr : {0x84u,0xbcu})
                for (unsigned sib : {0x77u,0xedu,0xffu}) for (uint32_t disp : {0u,9u,10u,127u,128u,0x7fffffffu,0x80000000u,0xffffffffu})
                    for (unsigned p2 : {0x09u,0x2fu,0x49u,0xc9u}) {
                        std::array<uint8_t,11> p{0x62,uint8_t(ext),0x7f,uint8_t(p2),uint8_t(op),uint8_t(mr),uint8_t(sib),
                            uint8_t(disp),uint8_t(disp>>8),uint8_t(disp>>16),uint8_t(disp>>24)};
                        if (!check(p,11,!wide || (op==0x7f && (p2&0x80)))) return 8;
                    }
        std::array<uint8_t,11>b{0x62,0xf1,0x7f,0xc9,0x6f,0xc0};
        if(cs_option(fast,CS_OPT_MNEMONIC,reinterpret_cast<size_t>(&names)) || !check(b,6,true))return 6;
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
