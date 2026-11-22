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
                length != (p[0] == 0xc5 ? 8 : 9) || cursor != p + length || left != n - length ||
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
        for (unsigned prefix : {2u,3u}) for(unsigned map=0;map<(prefix==2 ? 1u :32u);++map)
            for(unsigned opcode=0;opcode<256;++opcode) for(unsigned flags=0;flags<16;++flags)
                for(unsigned f=0;f<(wide && (prefix==2 || (map>=1 && map<=3)) ? 32u : 2u);++f) {
                    const unsigned n=prefix+6, dst=(opcode+f*3)&15,src=(opcode*3+f)&15;
                    const unsigned rxb=((dst>>3)<<2) | (f&3);
                    constexpr uint32_t ds[]={0U,1U,9U,10U,UINT32_MAX,0xfffffff6U,0x7fffffffU,0x80000000U};
                    const uint32_t disp=ds[f%8];
                    std::array<uint8_t,11> bytes{};
                    bytes[0]=uint8_t(prefix==2?0xc5:0xc4);
                    bytes[1]=uint8_t(((~rxb&7)<<5)|map);
                    bytes[prefix-1]=uint8_t((prefix==2?((~rxb&4)<<5):((flags&8)<<4))|((~src&15)<<3)|(flags&7));
                    bytes[prefix]=uint8_t(opcode);
                    bytes[prefix+1]=uint8_t(((dst&7)<<3)|(f==30?4:f==31?0xc5:5));
                    for (unsigned i=0;i<4;++i)bytes[prefix+2+i]=uint8_t(disp>>(8*i));
                    const bool reject=!wide||(prefix==3 && (map<1||map>3))||(flags&3)!=1||f>=30;
                    if (!check(bytes,n,reject)) {
                        std::fprintf(stderr,"VEX prefix=%u map=%u op=%02x flags=%u f=%u displacement=%x\\n",prefix,map,opcode,flags,f,disp);
                        return 3;
                    }
                    if (f==0)for(unsigned end=0;end<n;++end)if(!check(bytes,end,true))return 4;
                }
        std::array<uint8_t,11> supported{{0xc4,0x62,0xed,0xa8,0x05,0x36,0xc3,0x06,0,0x90,0x90}};
        if (!check(supported,11,false))return 5;
        for (auto opt : {CS_OPT_UNSIGNED,CS_OPT_TEXT}) {
            const auto on = opt==CS_OPT_TEXT ? CS_OPT_OFF : CS_OPT_ON;
            const auto off = opt==CS_OPT_TEXT ? CS_OPT_ON : CS_OPT_OFF;
            if (cs_option(fast,opt,on) || !check(supported,10,true) || cs_option(fast,opt,off))return 6;
        }
        if (cs_option(fast,CS_OPT_MNEMONIC,reinterpret_cast<size_t>(&names)) ||
            !check(supported,10,true))return 7;
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
