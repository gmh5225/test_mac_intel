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
        const unsigned profiles[] = {
            0, CS_MODE_RISCV_C, CS_MODE_RISCV_C|CS_MODE_RISCV_FD|CS_MODE_RISCV_A,
            CS_MODE_RISCV_C|CS_MODE_RISCV_ZCMP_ZCMT_ZCE|CS_MODE_RISCV_ZICFISS,
            CS_MODE_RISCV_C|CS_MODE_RISCV_E, CS_MODE_BIG_ENDIAN|CS_MODE_RISCV_C,
            CS_MODE_RISCV_C|CS_MODE_RISCV_THEAD|CS_MODE_RISCV_COREV|CS_MODE_RISCV_SIFIVE
        };
        for (unsigned step=0;step<sizeof(profiles)/sizeof(profiles[0]);++step) {
            if (!option(CS_OPT_TEXT,CS_OPT_ON)||!option(CS_OPT_DETAIL,CS_OPT_ON)||
                !option(CS_OPT_MODE,unsigned(bits)|profiles[step])||
                !option(CS_OPT_SKIPDATA,step==6?CS_OPT_ON:CS_OPT_OFF))return 4;
            for(unsigned word=0;word<=0xffff;++word) for(unsigned n : {1u,2u,4u}) {
                auto raw=area+page-n;
                raw[0]=uint8_t(word);
                if(n>=2)raw[1]=uint8_t(word>>8);
                if(n==4){raw[2]=0x82;raw[3]=0x6f;}
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
                    std::fprintf(stderr,"bits=%u phase=%u halfword=%x n=%u\n",unsigned(bits),step,word,n);
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
