#include "arch/X86/X86ScanAdapter.h"
#include <capstone/capstone.h>
#include <array>
#include <cinttypes>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

int main() {
    size_t page = size_t(sysconf(_SC_PAGESIZE));
    auto *mem = static_cast<uint8_t *>(mmap(nullptr, 2*page, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0));
    if (mem == MAP_FAILED || mprotect(mem+page,page,PROT_NONE)) return 1;
    uint64_t cases=0, good=0, hash=0xcbf29ce484222325ULL;
    const std::array<uint8_t,23> prefixes={0,0x66,0x67,0xf0,0xf2,0xf3,0x2e,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f};
    for (auto mode : {CS_MODE_16,CS_MODE_32,CS_MODE_64}) {
        csh a{}, b{};
        if (cs_open(CS_ARCH_X86,mode,&a)||cs_open(CS_ARCH_X86,mode,&b)) return 2;
        cs_opt_mnem full{X86_INS_UD2,"ud2"};
        if (cs_option(b,CS_OPT_MNEMONIC,(uintptr_t)&full))return 3;
        for (unsigned config=0;config<4;++config) {
            const auto syntax=config>=2? CS_OPT_SYNTAX_ATT:CS_OPT_SYNTAX_INTEL;
            const bool detail=config&1;
            for (auto h : {a,b}) {
                if (cs_option(h,CS_OPT_DETAIL,detail?CS_OPT_ON:CS_OPT_OFF)||cs_option(h,CS_OPT_SYNTAX,syntax))return 4;
            }
            for (auto prefix:prefixes) for (unsigned op:{0xfeu,0xffu})
              for (unsigned mr=0;mr<256;++mr) for (unsigned i=0;i<8;++i) {
                const uint8_t byte[]={0,1,9,10,0x7f,0x80,0xfe,0xff};
                const uint8_t sib[]={0,0x24,0x25,0x65,0x83,0xa4,0xdd,0xff};
                uint8_t bytes[12]={prefix,uint8_t(op),uint8_t(mr),sib[i],byte[i],0x80,0x7f,0x00,0xff,byte[7-i],0x90,0x90};
                size_t off=!prefix;
                for (size_t size=0;size<=sizeof(bytes)-off;++size) {
                    auto p=mem+page-size;memcpy(p,bytes+off,size);
                    cs_insn x{},y{}; cs_detail d{},e{};
                    memset(&d,0xa5,sizeof(d));e=d;
                    memset(&x,0x55,sizeof(x));x.illegal=x.is_alias=x.usesAliasDetails=false;y=x;
                    x.detail=detail?&d:nullptr;y.detail=detail?&e:nullptr;
                    const uint8_t *l=p,*r=p;size_t ls=size,rs=ls;uint64_t la=UINT64_MAX-op,ra=la;
                    bool ok=X86_disasmIterText(a,&l,&ls,&la,&x);
                    bool ref=cs_disasm_iter(b,&r,&rs,&ra,&y);
                    x.detail=y.detail;
                    if(ok!=ref||r!=l||ls!=rs||la!=ra||cs_errno(a)!=cs_errno(b)||
                       (ok&&(memcmp(&x,&y,sizeof(x))||memcmp(&d,&e,sizeof(d))))) {
                        fprintf(stderr,"unary or near branch record mismatch mode=%u opt=%u p=%02x opcode=%02x mr=%02x size=%zu\n",
                                unsigned(mode),config,prefix,op,mr,size);
                        fprintf(stderr,"sib %02x old %s %s extra %s %s, immediate %lld vs %lld, sizes %u %u, access %u %u\n",sib[i],y.mnemonic,y.op_str,x.mnemonic,x.op_str,
                                (long long)e.x86.operands[1].imm,(long long)d.x86.operands[1].imm,
                                e.x86.operands[1].size,d.x86.operands[1].size,e.x86.operands[0].access,d.x86.operands[0].access);
                        return 5;
                    }
                    // Include bytes left by failed and successful calls in the cross-build oracle.
                    x.detail=nullptr;
                    for(size_t i=0;i<sizeof(x);i+=8) {
                        uint64_t v=0;size_t len=sizeof(x)-i<8?sizeof(x)-i:8;
                        memcpy(&v,reinterpret_cast<const char*>(&x)+i,len);hash=(hash^v)*1099511628211ULL;
                    }
                    if(detail) {
                        const auto *ptr=reinterpret_cast<const uint8_t*>(&d);
                        for(size_t i=0;i<offsetof(cs_detail,x86)+sizeof(cs_x86);++i)hash=(hash^ptr[i])*1099511628211ULL;
                    }
                    ++cases;good+=ok;
                }
              }
        }
        cs_close(&a);cs_close(&b);
    }
    munmap(mem,2*page);
    printf("%" PRIu64 " %" PRIu64 " %" PRIu64 "\n",cases,good,hash);
}
