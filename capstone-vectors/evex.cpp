#include "arch/X86/X86ScanAdapter.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <sys/mman.h>
#include <unistd.h>
extern "C" uint32_t evex_word(const uint8_t *,size_t);
int main() {
    csh scan{}, full{};
    if(cs_open(CS_ARCH_X86,CS_MODE_64,&scan)||cs_open(CS_ARCH_X86,CS_MODE_64,&full)||cs_option(scan,CS_OPT_TEXT,CS_OPT_OFF)||cs_option(full,CS_OPT_DETAIL,CS_OPT_ON))return 2;
    cs_opt_mnem normal{X86_INS_UD2,"ud2"}; if(cs_option(full,CS_OPT_MNEMONIC,reinterpret_cast<size_t>(&normal)))return 2;
    cs_insn *insn=cs_malloc(full);if(!insn)return 2;
    const auto page=size_t(sysconf(_SC_PAGESIZE));auto mem=(uint8_t*)mmap(nullptr,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    if(mem==MAP_FAILED||mprotect(mem+page,page,PROT_NONE))return 2;
    uint8_t code[16]={0x62,0xf1,0x7d,0x48,0x6f,0xc0,0x25,0xaa,0x7f,0x00,0x23,0x55,0xff,0x67,0x12,0};
    uint64_t states=0,hits=0;
    auto check=[&](unsigned width){
        const uint8_t *p=mem+page-width;std::memcpy(mem+page-width,code,width);
        uint32_t a=0x44556678,b=a;auto x=X86_scanBatch(scan,p,width,0xfffffff8,&a,1),y=X86_scanNativeBatch(scan,p,width,0xfffffff8,&b,1);
        auto token=evex_word(p,width);if(x.count!=y.count||x.bytes!=y.bytes||a!=b)return false;
        if(token){
            size_t n=width;uint64_t ip=0xfffffff8;
            if(!cs_disasm_iter(full,&p,&n,&ip,insn)||token!=((insn->id<<8)|insn->size)||token!=a)return false;
            ++hits;
        }
        ++states;return true;
    };
    auto test=[&](unsigned n){if(!check(n)){for(auto c:code)std::fprintf(stderr,"%02x",c);std::fprintf(stderr," extent=%u\n",n);std::exit(5);}};
    for(unsigned op=0;op<256;++op)for(unsigned p3=0;p3<256;++p3)for(unsigned flags=0;flags<16;++flags){
        code[1]=uint8_t(((op+p3)<<4)|((op+p3+flags)&15));code[2]=uint8_t(((op^p3)&0x78)|(flags&7)|((flags&8)<<4));code[3]=uint8_t(p3);code[4]=uint8_t(op);code[5]=uint8_t(3*op+p3);
        test((op+flags)&15);test(15);
    }
    const uint8_t ops[]={0x00,0x6f,0x7f,0x19,0x1a,0x1b,0x25,0x39,0x3b,0x44,0xdb,0xdc,0xdd,0xde,0xdf,0xef,0xfe};
    for(auto op:ops)for(unsigned map=1;map<=3;++map)for(unsigned pw=0;pw<8;++pw)for(unsigned ll=0;ll<4;++ll)for(unsigned mr=0;mr<256;++mr){
        code[1]=uint8_t(0xf0|map);code[2]=uint8_t(0x7c|(pw&3)|((pw&4)<<5));code[3]=uint8_t((ll<<5)|8);code[4]=op;code[5]=uint8_t(mr);code[6]=uint8_t((mr&1)?0x25:0x24);
        test(15);test(6);test(7);test((op+mr)&15);
    }
    std::printf("%llu %llu\n",(unsigned long long)states,(unsigned long long)hits);
    cs_free(insn,1);cs_close(&scan);cs_close(&full);munmap(mem,page*2);
}
