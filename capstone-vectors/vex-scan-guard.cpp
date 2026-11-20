#include <capstone/capstone.h>
#include "arch/X86/X86ScanAdapter.h"
#include <sys/mman.h>
#include <unistd.h>
#include <cstdint>
#include <initializer_list>
#include <cstdio>
#include <cstdlib>
#include <cstring>

struct Probe {
    csh full{}, scan{};
    cs_insn *ordinary{}, *compact{};
    size_t page{};
    uint8_t *memory{};
    uint64_t cases{}, accepted{};

    Probe() {
        page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
        memory = static_cast<uint8_t *>(mmap(nullptr, 2 * page, PROT_READ | PROT_WRITE,
                                              MAP_PRIVATE | MAP_ANON, -1, 0));
        if (memory == MAP_FAILED || mprotect(memory + page, page, PROT_NONE) ||
            cs_open(CS_ARCH_X86, CS_MODE_64, &full) || cs_open(CS_ARCH_X86, CS_MODE_64, &scan) ||
            cs_option(full, CS_OPT_DETAIL, CS_OPT_ON) || cs_option(scan, CS_OPT_TEXT, CS_OPT_OFF))
            std::abort();
        cs_opt_mnem mnemonic{X86_INS_UD2, "ud2"};
        if (cs_option(full, CS_OPT_MNEMONIC, (size_t)&mnemonic)) std::abort();
        ordinary = cs_malloc(full);
        compact = cs_malloc(scan);
        if (!ordinary || !compact) std::abort();
    }
    ~Probe() {
        cs_free(ordinary, 1); cs_free(compact, 1);
        cs_close(&full); cs_close(&scan); munmap(memory, page * 2);
    }
    void check(const uint8_t (&bytes)[15]) {
        for (size_t n = 0; n <= sizeof(bytes); ++n) {
            uint8_t *edge = memory + page - n;
            std::memcpy(edge, bytes, n);
            const uint8_t *a = edge, *b = edge;
            size_t x = n, y = n;
            uint64_t ip = UINT64_MAX - 4, jp = ip;
            uint32_t output[2] = {0xa555aaaa, 0xaaa55555};
            const bool success = cs_disasm_iter(full, &a, &x, &ip, ordinary);
            const bool fast = cs_disasm_iter(scan, &b, &y, &jp, compact);
            const X86ScanBatchResult batch = X86_scanBatch(scan,edge,n,UINT64_MAX-4,output,1);
            const uint32_t expected = success ? ((ordinary->id << 8) | ordinary->size) : 0xa555aaaa;
            if (fast != success || x != y || a != b || ip != jp ||
                cs_errno(full) != cs_errno(scan) || batch.bytes != n - x ||
                batch.count != size_t(success) || output[0] != expected || output[1] != 0xaaa55555 ||
                (success && (ordinary->size != compact->size || ordinary->id != compact->id ||
                             std::memcmp(ordinary->bytes, compact->bytes, ordinary->size)))) {
                std::fprintf(stderr, "mismatch at n=%zu full=%d scan=%d full_id=%u scan_id=%u bytes=", n, success, fast, ordinary->id, compact->id);
                for (size_t i=0; i<n; ++i) std::fprintf(stderr, "%02x", bytes[i]);
                std::fputc('\n', stderr); std::exit(1);
            }
            ++cases; accepted += success;
        }
    }
};
int main() {
    Probe probe;
    uint8_t bytes[15] = {0x62,0,0,0,0,0,0x24,0x80,0xff,0xff,0xff,0x7f,0,0,0};
    for (unsigned family = 0; family < 2; ++family)
        for (unsigned wpp = 0; wpp < 8; ++wpp)
            for (unsigned ll = 0; ll < 4; ++ll) {
                bytes[1] = uint8_t(0xf1 + family);
                bytes[2] = uint8_t(0x7c | ((wpp & 4) << 5) | (wpp & 3));
                bytes[3] = uint8_t((ll << 5) | 8);
                bytes[4] = family ? 0x1a : 0x6f;
                for (unsigned modrm = 0; modrm < 256; ++modrm) {
                    bytes[5] = uint8_t(modrm);
                    bytes[6] = 0x24;
                    probe.check(bytes);
                    if (modrm == 4 || modrm == 0x44 || modrm == 0x84) {
                        for (unsigned sib=0;sib<256;++sib) {
                            bytes[6]=uint8_t(sib);
                            probe.check(bytes);
                        }
                    }
                    if ((modrm & 0x38) == 0) {
                        bytes[6] = 0x24;
                        for (unsigned field = 1; field <= 3; ++field)
                            for (unsigned bit = 0; bit < 8; ++bit) {
                                bytes[field] ^= uint8_t(1u << bit);
                                probe.check(bytes);
                                bytes[field] ^= uint8_t(1u << bit);
                            }
                    }
                }
            }
    if (cs_option(probe.full, CS_OPT_MODE, CS_MODE_32) ||
        cs_option(probe.scan, CS_OPT_MODE, CS_MODE_32)) std::abort();
    bytes[0] = 0xc5;
    for (unsigned payload : {0xc0u,0xc1u,0xc2u,0xc3u,0xc4u,0xc5u,0xc6u,0xc7u,
                             0xf8u,0xf9u,0xfau,0xfbu,0xfcu,0xfdu,0xfeu,0xffu}) {
        bytes[1] = uint8_t(payload);
        for (unsigned opcode=0; opcode<256; ++opcode) {
            bytes[2] = uint8_t(opcode);
            for (unsigned mr=0; mr<256; ++mr) {
                bytes[3] = uint8_t(mr); bytes[4] = 0x25;
                probe.check(bytes);
            }
        }
    }
    for (unsigned payload : {0xc0u,0xc4u,0xf8u,0xfcu})
        for (unsigned opcode : {0x10u,0x58u,0x6fu,0x70u,0x77u,0xadu,0xaeu,0xc2u})
            for (unsigned mr : {4u,0x44u,0x84u})
                for (unsigned sib=0; sib<256; ++sib) {
                    bytes[1]=uint8_t(payload); bytes[2]=uint8_t(opcode);
                    bytes[3]=uint8_t(mr); bytes[4]=uint8_t(sib);
                    probe.check(bytes);
                }
    std::printf("matched %llu page-ended extents (%llu decoded), full decoder vs public scan and private batch\n",
                (unsigned long long)probe.cases, (unsigned long long)probe.accepted);
}
