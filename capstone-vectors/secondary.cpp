#include "arch/X86/X86ScanAdapter.h"
#include <capstone/capstone.h>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

int main()
{
    const size_t page = size_t(sysconf(_SC_PAGESIZE));
    auto *block = static_cast<uint8_t *>(mmap(nullptr, 2 * page, PROT_READ | PROT_WRITE,
                                             MAP_PRIVATE | MAP_ANON, -1, 0));
    if (block == MAP_FAILED || mprotect(block + page, page, PROT_NONE)) return 1;
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) || cs_option(handle, CS_OPT_TEXT, CS_OPT_OFF))
        return 2;
    cs_insn *insn = cs_malloc(handle);
    if (!insn) return 3;
    uint64_t total = 0, accepted = 0, signature = 0;
    const uint8_t sibs[] = {0, 5, 0x24, 0xfd};
    for (unsigned opcode = 0; opcode < 256; ++opcode) {
        for (unsigned mr = 0; mr < 256; ++mr) {
            for (uint8_t sib : sibs) {
                uint8_t bytes[15] = {0x0f, uint8_t(opcode), uint8_t(mr), sib, 0x81,
                                     0xff, 5, 0xa6, 0x32, 0x08, 0x90, 0x7f, 0, 0x8a, 0x11};
                for (size_t n = 0; n <= sizeof(bytes); ++n) {
                    uint8_t *start = block + page - n;
                    std::memcpy(start, bytes, n);
                    const uint8_t *cursor = start;
                    size_t left = n;
                    uint64_t address = UINT32_C(0xfffffffc);
                    bool ok = cs_disasm_iter(handle, &cursor, &left, &address, insn);
                    uint32_t output[] = {0xfedcba98, 0x01234567};
                    auto batch = X86_scanNativeBatch(handle, start, n, UINT32_C(0xfffffffc), output, 1);
                    if (batch.count != size_t(ok) || batch.bytes != n - left ||
                        (ok ? output[0] != ((insn->id << 8) | insn->size) : output[0] != 0xfedcba98) ||
                        output[1] != 0x01234567 || cursor != start + batch.bytes) {
                        std::fprintf(stderr, "opcode=%02x modrm=%02x sib=%02x n=%zu public=%d/%08x/%zu batch=%zu/%08x/%zu\n",
                                     opcode,mr,sib,n,ok,ok ? insn->id : 0,n-left,batch.count,output[0],batch.bytes);
                        return 4;
                    }
                    signature = signature * 131 + output[0] + batch.bytes;
                    accepted += ok;
                    ++total;
                }
            }
        }
    }
    std::printf("%" PRIu64 " %" PRIu64 " %" PRIu64 "\n",total,accepted,signature);
    cs_free(insn, 1);
    cs_close(&handle);
    return munmap(block, 2 * page) != 0;
}
