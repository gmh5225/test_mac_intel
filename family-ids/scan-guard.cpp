#include <capstone/capstone.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>

struct Library {
    void *lib;
    decltype(&cs_open) open;
    decltype(&cs_option) option;
    decltype(&cs_disasm_iter) next;
    decltype(&cs_close) close;
    explicit Library(const char *name) : lib(dlopen(name, RTLD_NOW | RTLD_LOCAL)),
        open((decltype(open))dlsym(lib, "cs_open")), option((decltype(option))dlsym(lib,"cs_option")),
        next((decltype(next))dlsym(lib, "cs_disasm_iter")), close((decltype(close))dlsym(lib, "cs_close")) {}
};

int main(int argc, char **argv) {
    if (argc != 3) return 1;
    Library a(argv[1]), b(argv[2]);
    const size_t page = sysconf(_SC_PAGESIZE);
    auto area = (uint8_t *)mmap(nullptr, 2 * page, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (!a.lib || !b.lib || area == MAP_FAILED || mprotect(area + page, page, PROT_NONE)) return 2;
    uint64_t calls = 0, valid = 0, rejected = 0;
    for (auto bits : {CS_MODE_RISCV32, CS_MODE_RISCV64}) {
        csh x, y;
        if (a.open(CS_ARCH_RISCV, bits, &x) || b.open(CS_ARCH_RISCV, bits, &y)) return 3;
        auto option = [&](cs_opt_type key, size_t value) {
            return a.option(x,key,value) == b.option(y,key,value);
        };
        for (unsigned step = 0; step != 8; ++step) {
            const bool text = step == 2 || step == 5;
            const bool detail = step == 1 || step == 5;
            if (!option(CS_OPT_TEXT,text ? CS_OPT_ON : CS_OPT_OFF) || !option(CS_OPT_DETAIL,detail ? CS_OPT_ON : CS_OPT_OFF) ||
                !option(CS_OPT_MODE,unsigned(bits) | (step==3 ? unsigned(CS_MODE_RISCV_E) : step==4 ? unsigned(CS_MODE_BIG_ENDIAN) : 0U)) ||
                !option(CS_OPT_SKIPDATA, step == 6 ? CS_OPT_ON : CS_OPT_OFF)) return 4;
            for (unsigned major : {0x03U,0x13U,0x17U,0x23U,0x37U,0x63U,0x67U,0x6fU,0x73U,0x1fU}) for (unsigned rd = 0; rd < 32; ++rd)
            for (unsigned seed = 0; seed < 97; ++seed) for (unsigned n = 0; n <= 5; ++n) {
                uint32_t word = (uint32_t(seed * 0x9e3779b9U) & 0xfffff000U) | rd << 7 | major;
                auto raw = area + page - n;
                for (unsigned i=0; i<n; ++i) raw[i]=i<4?uint8_t(word>>(i*8)):0xcc;
                cs_detail dx,dy; cs_insn ix,iy;
                std::memset(&dx,0xa5,sizeof(dx)); std::memcpy(&dy,&dx,sizeof(dx));
                std::memset(&ix,0x5a,sizeof(ix)); ix.is_alias=ix.illegal=ix.usesAliasDetails=false;
                std::memcpy(&iy,&ix,sizeof(ix));
                ix.detail=&dx; iy.detail=&dy;
                const uint8_t *px=raw,*py=raw; size_t nx=n,ny=n; uint64_t ax=0x1234,ay=ax;
                bool vx=a.next(x,&px,&nx,&ax,&ix), vy=b.next(y,&py,&ny,&ay,&iy);
                if ((ix.detail==&dx)!=(iy.detail==&dy) || (ix.detail==nullptr)!=(iy.detail==nullptr)) return 6;
                ix.detail=iy.detail=nullptr;
                if(vx!=vy || px!=py || nx!=ny || ax!=ay || std::memcmp(&ix,&iy,sizeof(ix)) || std::memcmp(&dx,&dy,sizeof(dx))) {
                    std::fprintf(stderr,"bits=%u phase=%u opcode=%x rd=%u seed=%u n=%u\n",unsigned(bits),step,major,rd,seed,n);
                    return 7;
                }
                ++calls; valid+=vx; rejected+=!vx;
            }
        }
        a.close(&x);b.close(&y);
    }
    munmap(area,2*page);
    std::printf("%llu %llu %llu\n",(unsigned long long)calls,(unsigned long long)valid,(unsigned long long)rejected);
    return !(calls && valid && rejected);
}
