#define main inspect_real_records
#include "public-records.cpp"
#undef main
#include <array>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    const size_t page = size_t(sysconf(_SC_PAGESIZE));
    auto *memory = static_cast<uint8_t *>(mmap(nullptr, page * 2,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0));
    if (memory == MAP_FAILED || mprotect(memory + page, page, PROT_NONE)) return 3;
    uint64_t checked = 0, decoded = 0;
    for (auto mode : { CS_MODE_32, CS_MODE_64 }) {
        Api baseline(argv[1], mode), candidate(argv[2], mode);
        for (auto skip : { CS_OPT_OFF, CS_OPT_ON }) {
            for (Api *api : { &baseline, &candidate })
                if (api->option(api->handle, CS_OPT_TEXT, CS_OPT_OFF) ||
                    api->option(api->handle, CS_OPT_SKIPDATA, skip)) return 4;
            for (unsigned opcode = 0; opcode < 256; ++opcode) {
                for (unsigned mr = 0; mr < 256; ++mr) {
                    bool sib = (mr & 7) == 4 && mr < 0xc0;
                    unsigned count = sib && (opcode == 0x8b || opcode == 0x83 ||
                        opcode == 0xff || opcode == 0xf7) ? 256 : 4;
                    for (unsigned s = 0; s < count; ++s) {
                        const unsigned enc = count == 256 ? s : std::array<unsigned,4>{0,0x24,0x25,0xff}[s];
                        const uint8_t bytes[] = {uint8_t(opcode),uint8_t(mr),uint8_t(enc),
                            0x80,0x7f,0xff,0x81,0xa5,0x18,0xb7,0x79,0x6a};
                        for (size_t length : {0U,1U,2U,3U,4U,5U,6U,7U,8U,11U}) {
                            uint8_t *p = memory + page - length;
                            if (length) std::memcpy(p, bytes, length);
                            cs_insn a,b;
                            std::memset(&a, 0xa5, sizeof(a)); a.detail = nullptr;
                            std::memcpy(&b, &a, sizeof(b));
                            const uint8_t *pa=p, *pb=p; size_t na=length, nb=length;
                            uint64_t ia=UINT64_C(0xfffffff0)+s, ib=ia;
                            bool ra=baseline.iter(baseline.handle,&pa,&na,&ia,&a);
                            bool rb=candidate.iter(candidate.handle,&pb,&nb,&ib,&b);
                            if (ra!=rb || pa!=pb || na!=nb || ia!=ib ||
                                baseline.error(baseline.handle)!=candidate.error(candidate.handle) ||
                                std::memcmp(&a,&b,sizeof(a))) {
                                std::fprintf(stderr,"mode=%u skip=%u op=%02x mr=%02x sib=%02x n=%zu accepted=%d/%d id=%u/%u len=%u/%u\n",
                                    unsigned(mode),unsigned(skip),opcode,mr,enc,length,ra,rb,a.id,b.id,a.size,b.size);
                                return 1;
                            }
                            ++checked; decoded += ra;
                        }
                    }
                }
            }
        }
    }
    if (munmap(memory,2*page)) return 5;
    std::printf("%llu %llu\n",(unsigned long long)checked,(unsigned long long)decoded);
}
