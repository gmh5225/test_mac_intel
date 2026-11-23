#include <capstone/capstone.h>
#include <array>
#include <cstddef>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

extern "C" bool observed_plain(csh, bool, const uint8_t *, size_t,
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
            const unsigned mod = bytes[5] >> 6, rm = bytes[5] & 7;
            const unsigned length_expected = 6 + (mod == 2 || (!mod && rm == 5) ? 4 : mod);
            const uint8_t *cursor = p;
            size_t left = n;
            uint64_t ip = reference.address;
            if (!cs_disasm_iter(ordinary, &cursor, &left, &ip, &reference) ||
                length != length_expected || cursor != p + length || left != n - length ||
                ip != actual.address + length || actual.id != reference.id ||
                actual.size != length || reference.size != length ||
                std::memcmp(actual.bytes, reference.bytes, sizeof(actual.bytes)) ||
                std::memcmp(actual.mnemonic, reference.mnemonic, sizeof(actual.mnemonic)) ||
                std::memcmp(actual.op_str, reference.op_str, sizeof(actual.op_str)) ||
                (detail && std::memcmp(&act, &ref, offsetof(cs_detail, x86) + sizeof(cs_x86))))
                return false;
            actual.detail = reference.detail;
            return std::memcmp(&actual, &reference, sizeof(actual)) == 0 &&
                   std::memcmp(&act, &ref, sizeof(act)) == 0;
        };
        for (unsigned map=0;map<16;++map) for(unsigned opcode=0;opcode<256;++opcode)
            for(unsigned flags=0;flags<16;++flags) for(unsigned ll=0;ll<4;++ll)
                for(unsigned f=0;f<(wide && map>=1 && map<=3 ? 32u : 2u);++f) {
                    const unsigned src=(f<8 ? 0 : (f+opcode)&31),dst=(opcode+f*3)&31,rm=(f*5+flags)&31;
                    const unsigned mr = ((dst&7)<<3)|(f==31 ? (rm&7)|0x40 : 5);
                    constexpr uint32_t ds[]={0U,1U,9U,10U,UINT32_MAX,0xfffffff6U,
                        0x7fffffffU,0x80000000U,0x3340U,0xffe20310U};
                    const uint32_t disp=ds[(f+flags)%10];
                    std::array<uint8_t,11> bytes{{0x62,static_cast<uint8_t>(map|
                        ((dst&8)?0:0x80)|((f&3)<<5)|(~dst&16)),
                        static_cast<uint8_t>(((flags&4)<<5)|((~src&15)<<3)|((flags&8)?0:4)|(flags&3)),
                        static_cast<uint8_t>((ll<<5)|((src&16)?0:8)|(f==29?0x81:f==30?0x10:0)),static_cast<uint8_t>(opcode),
                        static_cast<uint8_t>(mr),uint8_t(disp),uint8_t(disp>>8),uint8_t(disp>>16),
                        uint8_t(disp>>24),0x90}};
                    const bool reject=!wide||map<1||map>3||(flags&8)||ll==3||f==29||f==30||(f==31 && (mr&7)==4);
                    if (!check(bytes,10,reject)) {
                        std::fprintf(stderr,"EVEX map=%u op=%02x flags=%u ll=%u reg configuration=%u\\n",map,opcode,flags,ll,f);
                        return 3;
                    }
                    if (f==0) for(unsigned end=0;end<10;++end) if(!check(bytes,end,true))return 4;
                }
        for (unsigned map = 1; map <= 3; ++map) for (unsigned op = 0; op < 256; ++op)
            for (unsigned key = 0; key < 24; ++key) for (unsigned addr = 0; addr < 32; ++addr)
                for (unsigned ext = 0; ext < 4; ++ext) {
                    const unsigned mod = addr >> 3, rm = addr & 7, ll = key % 3;
                    const unsigned ds = mod == 2 || (!mod && rm == 5) ? 4 : mod;
                    const unsigned dst = (ext * 7 + op + addr) & 31, src = dst ^ 31;
                    const uint32_t edge[] = {0, 1, 9, 10, 127, 128, 255, 0x7fffffff, 0x80000000, 0xffffffff};
                    const unsigned v = edge[(key + ext + rm + op) % 10];
                    std::array<uint8_t,11> b{0x62,
                        uint8_t(map | ((dst & 8) ? 0 : 0x80) | (ext << 5) | (~dst & 16)),
                        uint8_t(((key / 12) << 7) | ((~src & 15) << 3) | 4 | (key / 3 % 4)),
                        uint8_t((ll << 5) | ((src & 16) ? 0 : 8)), uint8_t(op),
                        uint8_t((mod << 6) | ((dst & 7) << 3) | rm),
                        uint8_t(v), uint8_t(v >> 8), uint8_t(v >> 16), uint8_t(v >> 24), 0};
                    if (!check(b, 6 + ds, !wide || rm == 4 || mod == 3)) {
                        std::fprintf(stderr, "EVEX op=%x map=%u key=%u addr=%u ext=%u\n", op, map, key, addr, ext);
                        return 8;
                    }
                    if (ds && ext == 0 && !check(b, 5 + ds, true)) return 9;
                }
        std::array<uint8_t,11> supported{{0x62,0xf1,0x65,0x48,0xfe,0x1d,0x73,0x70,0x33,0x00,0}};
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
    munmap(area, page*2);
    std::printf("%llu %llu %llu\n", (unsigned long long)trials,
                (unsigned long long)hits32,(unsigned long long)hits64);
}
