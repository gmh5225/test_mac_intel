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
        auto check = [&](const std::array<uint8_t, 15>& bytes, unsigned n,
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
                return false;
            actual.detail = reference.detail;
            if (std::memcmp(&actual, &reference, sizeof(actual)) ||
                std::memcmp(&act, &ref, sizeof(act))) return false;
            return true;
        };
        for (unsigned rex=0;rex<=(wide?16:0);++rex)
        for (unsigned op: {0x80u,0x81u,0x82u,0x83u,0xc7u}) for (unsigned mr=0;mr<256;++mr) {
            const unsigned mod=mr>>6,rm=mr&7,field=(mr>>3)&7,lead=bool(rex);
            const bool indexed=rm==4 && mod<3,eligible=wide && field==7 && mod!=3 && op!=0x82 && op!=0xc7;
            for(unsigned sib=0;sib<(eligible&&indexed?256u:1u);++sib) {
                const unsigned disp=mod==2 || (mod==0 && (rm==5 || (indexed && (sib&7)==5))) ? 4 : (mod==1);
                const unsigned off=lead+2+indexed+disp,len=off+(op==0x81 || op==0xc7?4:1);
                std::array<uint8_t,15>b{};if(rex)b[0]=0x3f+rex;b[lead]=op;b[lead+1]=mr;
                if(indexed)b[lead+2]=sib;
                if(disp){b[off-disp]=0x80;b[off-1]=0xff;}
                for (uint32_t imm:{0u,127u,128u,255u,0x7fffffffu,0x80000000u,0xffffffffu}) {
                    for(unsigned k=0;k<4;++k)b[off+k]=imm>>(8*k);
                    if(!check(b,len,!eligible)){std::fprintf(stderr,"cmp rex %u op %x mr %x sib %x imm %x\\n",rex,op,mr,sib,imm);return 3;}
                }
                for(unsigned n=0;n<len;++n)if(!check(b,n,true)){std::fprintf(stderr,"short rex %u op %x mr %x sib %x n %u\\n",rex,op,mr,sib,n);return 4;}
            }
        }
        std::array<uint8_t,15>b{0x48,0x83,0x38,0xff};
        if(cs_option(fast,CS_OPT_MNEMONIC,reinterpret_cast<size_t>(&names)) || !check(b,4,true))return 6;
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
