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
    if (cs_open(CS_ARCH_X86,CS_MODE_32,&fast) || cs_open(CS_ARCH_X86,CS_MODE_32,&slow)) return 2;
    cs_opt_mnem custom{X86_INS_UD2,"unused-ud2"};
    if (cs_option(slow,CS_OPT_MNEMONIC,(uintptr_t)&custom)) return 3;
    uint64_t checked=0, decoded=0, hash=0xcbf29ce484222325;
    const uint8_t prefixes[][2]={{},{0x26},{0x2e},{0x36},{0x3e},{0x64},{0x65},{0x66},{0x67},{0x64,0x67},{0x64,0x66},{0x65,0x64},{0xf0}};
    const unsigned lengths[]={0,1,1,1,1,1,1,1,1,2,2,2,1};
    for (auto syntax : {CS_OPT_SYNTAX_INTEL,CS_OPT_SYNTAX_MASM,CS_OPT_SYNTAX_ATT}) {
      if(cs_option(fast,CS_OPT_SYNTAX,syntax)||cs_option(slow,CS_OPT_SYNTAX,syntax))return 4;
      for (auto detail : {CS_OPT_OFF,CS_OPT_ON}) {
        if(cs_option(fast,CS_OPT_DETAIL,detail)||cs_option(slow,CS_OPT_DETAIL,detail))return 4;
        for (unsigned prefix=0;prefix<sizeof(lengths)/sizeof(lengths[0]);++prefix) for(unsigned op=0xa0;op<=0xa3;++op) {
            for(unsigned pattern=0;pattern<528;++pattern) {
                static const uint32_t edge[]={0,1,8,9,10,15,16,127,128,255,256,65535,0x7fffffff,0x80000000,0xfffffffe,0xffffffff};
                unsigned value=pattern<16 ? edge[pattern] : pattern<272 ? pattern-16 : (pattern-272)*UINT32_C(0x01010101);
                uint8_t bytes[8]={0};unsigned n=lengths[prefix];memcpy(bytes,prefixes[prefix],n);bytes[n++]=uint8_t(op);
                for(unsigned k=0;k<4;++k)bytes[n++]=uint8_t(value>>(k*8));bytes[n++]=0x90;
                for(unsigned size=0;size<=n;++size) {
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
                        fprintf(stderr,"mismatch prefix=%02x opcode=%02x syntax=%u pattern=%u size=%u detail=%u %s / %s\n",prefix,op,unsigned(syntax),pattern,size,unsigned(detail),ok?a.op_str:"invalid",expected?b.op_str:"invalid");
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
    }
    cs_close(&fast);cs_close(&slow);munmap(page,page_size*2);
    printf("%" PRIu64 " %" PRIu64 " %" PRIu64 "\n",checked,decoded,hash);
}
