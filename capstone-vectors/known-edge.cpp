#include <capstone/capstone.h>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>

using Writer = bool(const uint8_t *, size_t, cs_insn *, uint16_t *);

int main(int argc, char **argv)
{
    if (argc != 3) return 1;
    auto lookup = [](const char *image) {
        void *library = dlopen(image, RTLD_NOW | RTLD_LOCAL);
        return library ? reinterpret_cast<Writer *>(dlsym(library, "measure_vex2")) : nullptr;
    };
    Writer *reference = lookup(argv[1]), *candidate = lookup(argv[2]);
    if (!reference || !candidate) return 2;
    const long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) return 3;
    auto *region = static_cast<uint8_t *>(mmap(nullptr, 2*page, PROT_READ | PROT_WRITE,
                                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (region == MAP_FAILED || mprotect(region+page,page,PROT_NONE)) return 4;
    size_t trials = 0, accepts = 0;
    for (unsigned flags=0; flags<256; ++flags) {
        for (unsigned opcode=0; opcode<256; ++opcode) {
            for (unsigned modrm : {0x00,0x04,0x05,0x35,0x39,0x44,0x84,0xbf,0xc0,0xd5,0xfe,0xff}) {
                const uint8_t sib = uint8_t(flags*13 + modrm);
                const std::array<uint8_t,10> source = {0xc5,uint8_t(flags),uint8_t(opcode),
                    uint8_t(modrm),sib,0x80,0xff,0x7f,0x01,0x40};
                for (size_t n=1; n<=source.size(); ++n) {
                    uint8_t *p = region+page-n;
                    std::memcpy(p,source.data(),n);
                    for (unsigned details=0;details<2;++details) {
                        cs_insn a, b;
                        cs_detail da, db;
                        std::memset(&a,0xa5,sizeof(a));
                        a.is_alias=a.usesAliasDetails=a.illegal=false;
                        a.address=0x1111222233334444ULL;
                        std::memcpy(&b,&a,sizeof(b));
                        a.detail=details?&da:nullptr; b.detail=details?&db:nullptr;
                        std::memset(&da,0x5a,sizeof(da));
                        std::memset(&db,0x5a,sizeof(db));
                        uint16_t len1=12345, len2=12345;
                        bool ok1=reference(p,n,&a,&len1), ok2=candidate(p,n,&b,&len2);
                        if (a.detail!=(details?&da:nullptr) || b.detail!=(details?&db:nullptr)) return 5;
                        a.detail=b.detail=nullptr;
                        if (ok1!=ok2 || len1!=len2 || std::memcmp(&a,&b,sizeof(a)) ||
                            std::memcmp(&da,&db,sizeof(da))) {
                            std::fprintf(stderr,"C5 %02x %02x %02x, %zu bytes, details %u\n",flags,opcode,modrm,n,details);
                            return 6;
                        }
                        ++trials;
                        accepts+=ok1;
                    }
                }
            }
        }
    }
    if (munmap(region,2*page)) return 7;
    std::printf("%zu %zu\n",trials,accepts);
}
