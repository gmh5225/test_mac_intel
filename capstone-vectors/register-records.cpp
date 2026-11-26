#include <capstone/capstone.h>
#include "arch/X86/X86ScanAdapter.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

struct Reader {
    csh handle{};
    cs_insn *record{};
    decltype(&cs_disasm_iter) next{};
    uint64_t hash = 14695981039346656037ULL;
    uint32_t good{}, bad{};

    void mix(const void *p, size_t n) {
        auto *s = static_cast<const uint8_t *>(p);
        while (n--) hash = (hash ^ *s++) * 1099511628211ULL;
    }
    void check(const uint8_t *bytes, size_t size) {
        auto *detail = record->detail;
        std::memset(record, 0, sizeof(*record));
        std::memset(record->mnemonic, 0xa5, sizeof(record->mnemonic));
        std::memset(record->op_str, 0xa5, sizeof(record->op_str));
        if (detail) std::memset(detail, 0, sizeof(*detail));
        record->detail = detail;
        auto *cursor = bytes;
        size_t left = size;
        uint64_t ip = 0x100001ff5ULL;
        bool accepted = next(handle, &cursor, &left, &ip, record);
        if (accepted) {
            ++good;
            if (!record->size || record->size > size || left != size-record->size ||
                cursor != bytes+record->size || ip != 0x100001ff5ULL+record->size)
                std::abort();
        } else {
            ++bad;
        }
        auto offset = cursor-bytes;
        mix(&accepted,sizeof(accepted));
        mix(&offset,sizeof(offset));
        mix(&left,sizeof(left));
        mix(&ip,sizeof(ip));
        record->detail = nullptr;
        mix(record,sizeof(*record));
        if (detail) mix(detail,offsetof(cs_detail,x86)+sizeof(cs_x86));
        record->detail = detail;
    }
};
int main() {
    for (auto mode : {CS_MODE_32, CS_MODE_64}) {
        std::array<Reader,4> readers;
        for (size_t i=0;i<readers.size();++i) {
            auto &r = readers[i];
            if (cs_open(CS_ARCH_X86,mode,&r.handle) ||
                cs_option(r.handle,CS_OPT_DETAIL,(i&1)?CS_OPT_ON:CS_OPT_OFF))
                return 1;
            r.next = i<2 ? cs_disasm_iter : X86_disasmIterText;
            if (!(r.record=cs_malloc(r.handle))) return 2;
        }
        for (unsigned rex : {0u,0x40u,0x41u,0x44u,0x48u,0x4bu,0x4fu}) {
            if (mode==CS_MODE_32 && rex) continue;
            for (unsigned op : {0x00,0x03,0x31,0x38,0x80,0x83,0x84,0x85,0x88,
                                0x89,0x8a,0x8b,0x8d,0xc1,0xff,0x0fb6,0x0fb7,
                                0x0fbe,0x0fbf}) {
                for (unsigned rm=0;rm<256;++rm) {
                    std::array<uint8_t,16> buf{};
                    unsigned n=0;
                    if (rex) buf[n++]=uint8_t(rex);
                    if (op>255) buf[n++]=0x0f;
                    buf[n++]=uint8_t(op);
                    buf[n++]=uint8_t(rm);
                    for (unsigned sib : {0x24u,0x65u,0x92u,0xfdu}) {
                        if (sib!=0x24 && ((rm&7)!=4 || rm>=192)) continue;
                        buf[n]=uint8_t(sib);
                        buf[n+1]=0x81; buf[n+2]=0xab; buf[n+3]=0x25; buf[n+4]=0xfe;
                        for (auto &r : readers) {
                            r.check(buf.data(),n+6);
                            r.check(buf.data(),(rm+op+rex)%n);
                        }
                    }
                }
            }
        }
        for (auto &r : readers) {
            if (!r.good || !r.bad) return 3;
            std::printf("%u %u %016llx\n",r.good,r.bad,(unsigned long long)r.hash);
            cs_free(r.record,1); cs_close(&r.handle);
        }
    }
}
