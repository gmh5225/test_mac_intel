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
            auto check = [&](const uint8_t *bytes, size_t length, unsigned salt) {
                uint8_t *p = memory + page - length;
                if (length) std::memcpy(p, bytes, length);
                cs_insn a,b;
                std::memset(&a, 0xa5, sizeof(a)); a.detail = nullptr;
                std::memcpy(&b, &a, sizeof(b));
                const uint8_t *pa=p, *pb=p; size_t na=length, nb=length;
                uint64_t ia=UINT64_C(0xfffffff0)+salt, ib=ia;
                bool ra=baseline.iter(baseline.handle,&pa,&na,&ia,&a);
                bool rb=candidate.iter(candidate.handle,&pb,&nb,&ib,&b);
                if (ra!=rb || pa!=pb || na!=nb || ia!=ib ||
                    baseline.error(baseline.handle)!=candidate.error(candidate.handle) ||
                    std::memcmp(&a,&b,sizeof(a))) {
                    std::fprintf(stderr,"mode=%u skip=%u op=%02x mr=%02x sib=%02x n=%zu accepted=%d/%d id=%u/%u len=%u/%u\n",
                        unsigned(mode),unsigned(skip),unsigned(bytes[0]),unsigned(bytes[1]),unsigned(bytes[2]),length,ra,rb,a.id,b.id,a.size,b.size);
                    return false;
                }
                ++checked; decoded += ra;
                return true;
            };
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
                            if (!check(bytes, length, s)) return 1;
                        }
                    }
                }
            }
            // Cross every opcode with the prefix families handled by the batch reader.
            for (unsigned op=0;op<256;++op) {
                for (unsigned mr : {0U, 4U, 5U, 0x24U, 0x44U, 0x85U, 0xc0U, 0xffU}) {
                    for (unsigned variant=0;variant<32;++variant) {
                        std::array<uint8_t,16> bytes{};
                        size_t i=0; const auto put=[&](unsigned b){bytes[i++]=uint8_t(b);};
                        if (variant<8) {
                            put(0x40+variant*2+(op&1)); if (mr&4) put(0x0f);
                        } else if (variant<16) {
                            put(std::array<unsigned,4>{0x66,0xf2,0xf3,0x66}[variant&3]);
                            if (variant&4) put(0x48+(op&7));
                            put(0x0f);
                        } else if (variant<20) {
                            put(0xc5); put((op*41+(variant&3))&255);
                        } else if (variant<24) {
                            put(0xc4); put(((op*23)&0xe0)+1+variant%3); put(op*41+mr);
                        } else {
                            put(0x62); put(((op*23)&0xf0)+1+variant%3);
                            put(((op*41)&0xfc)+(variant&3)); put(((variant-24)*32)+(mr&31));
                        }
                        put(op);put(mr);put(0x25);put(1);put(0xff);put(0x7f);put(0x80);put(0x51);
                        for (size_t n=1;n<=i;++n)
                            if (!check(bytes.data(),n,variant)) return 1;
                    }
                }
            }
        }
    }
    if (munmap(memory,2*page)) return 5;
    std::printf("%llu %llu\n",(unsigned long long)checked,(unsigned long long)decoded);
}
