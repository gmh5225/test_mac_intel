#include "arch/X86/X86ScanAdapter.h"
#include <capstone/capstone.h>
#include <array>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

int main() {
    size_t page_size = size_t(sysconf(_SC_PAGESIZE));
    auto *page = static_cast<uint8_t *>(mmap(nullptr, page_size*2, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0));
    if (page==MAP_FAILED || mprotect(page+page_size,page_size,PROT_NONE)) return 1;
    csh fast{}, slow{};
    if (cs_open(CS_ARCH_X86,CS_MODE_64,&fast) || cs_open(CS_ARCH_X86,CS_MODE_64,&slow)) return 2;
    cs_opt_mnem custom{X86_INS_UD2,"unused-ud2"};
    if (cs_option(slow,CS_OPT_MNEMONIC,(uintptr_t)&custom)) return 3;
    uint64_t checked=0, decoded=0, hash=0xcbf29ce484222325;
    for (auto detail : {CS_OPT_OFF,CS_OPT_ON}) {
        if(cs_option(fast,CS_OPT_DETAIL,detail)||cs_option(slow,CS_OPT_DETAIL,detail))return 4;
        for (unsigned prefix : {2u,3u}) for(unsigned op : {0x90u,0x91u,0x92u,0x10u,0x11u,0x12u,0x6eu,0x7eu,0x6fu}) {
            for(unsigned mr=0;mr<256;mr+=1)for(unsigned pattern=0;pattern<64;++pattern) {
                static const uint32_t disp[]={0,9,10,0x7f,0xffffffe0,0x80000000,0x12345678,0xffffffff};
                const unsigned sib=pattern >= 32 && (pattern % 4 == 0) ? 0x24 : (pattern*97u+(mr>>3)*19u)&255;
                uint8_t bytes[11]={uint8_t(prefix==3?0xc4:0xc5)};
                unsigned flags=(pattern&1?0x80:0)|((pattern>>1)&1)|0x78;
                if(op<0x20)flags=(flags & ~0x80u)|2u; else if(op<0x80)flags=(flags & ~3u)|1u;
                if((pattern&31)>=24)flags^=4u<<(pattern%4);
                if(prefix==3){bytes[1]=uint8_t((((pattern^(pattern>>3))&7)<<5)|1);bytes[2]=uint8_t(flags);}
                else bytes[1]=uint8_t((flags&0x7f)|(pattern&4?0x80:0));
                bytes[prefix]=uint8_t(op);bytes[prefix+1]=uint8_t(mr);
                bytes[prefix+2]=uint8_t(sib);
                uint32_t value=disp[pattern&7];
                for(unsigned k=0;k<4;++k)bytes[prefix+3+k]=uint8_t(value>>(k*8));
                for(unsigned size=0;size<=sizeof(bytes);++size) {
                    uint8_t *start=page+page_size-size;
                    memcpy(start,bytes,size);
                    cs_insn a,b;cs_detail x,y;
                    memset(&a,0xa5,sizeof(a));memset(&b,0xa5,sizeof(b));
                    memset(&x,0xa5,sizeof(x));memset(&y,0xa5,sizeof(y));
                    a.detail=detail==CS_OPT_ON?&x:nullptr;b.detail=detail==CS_OPT_ON?&y:nullptr;
                    const uint8_t *pc=start,*ref=start;
                    size_t left=size,remaining=size;
                    uint64_t ip=0x100000001,base=ip;
                    bool ok=X86_disasmIterText(fast,&pc,&left,&ip,&a);
                    bool expected=cs_disasm_iter(slow,&ref,&remaining,&base,&b);
                    a.detail=b.detail;
                    if(ok!=expected||pc!=ref||ip!=base||left!=remaining||cs_errno(fast)!=cs_errno(slow)||
                       (ok && (memcmp(&a,&b,sizeof(a))||memcmp(&x,&y,sizeof(x))))) {
                        fprintf(stderr,"mismatch prefix=%02x opcode=%02x mr=%02x pattern=%u size=%u detail=%u %s / %s\n",prefix,op,mr,pattern,size,unsigned(detail),ok?a.op_str:"invalid",expected?b.op_str:"invalid");
                        return 5;
                    }
                    ++checked;decoded+=ok;
                    hash=(hash ^ (ok ? (uint64_t(a.id)<<8)|a.size : 0))*UINT64_C(1099511628211);
                    if(ok && detail==CS_OPT_ON) {
                        cs_regs ar{},aw{},br{},bw{};uint8_t an{},am{},bn{},bm{};
                        a.detail=&x;
                        if(cs_regs_access(fast,&a,ar,&an,aw,&am)||cs_regs_access(slow,&b,br,&bn,bw,&bm)||
                           an!=bn||am!=bm||memcmp(ar,br,sizeof(ar))||memcmp(aw,bw,sizeof(aw)))return 6;
                    }
                }
            }
        }
    }
    cs_close(&fast);cs_close(&slow);munmap(page,page_size*2);
    printf("%" PRIu64 " %" PRIu64 " %" PRIu64 "\n",checked,decoded,hash);
}
