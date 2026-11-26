#include "arch/X86/X86ScanAdapter.h"
#include <capstone/capstone.h>
#include <array>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

int main() {
#ifdef _WIN32
    SYSTEM_INFO info; GetSystemInfo(&info);
    size_t page_size=info.dwPageSize;
    auto *page=static_cast<uint8_t *>(VirtualAlloc(nullptr,2*page_size,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE));
    DWORD old_protect;
    if (!page || !VirtualProtect(page+page_size,page_size,PAGE_NOACCESS,&old_protect)) return 1;
#else
    size_t page_size = size_t(sysconf(_SC_PAGESIZE));
    auto *page = static_cast<uint8_t *>(mmap(nullptr, page_size*2, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0));
    if (page==MAP_FAILED || mprotect(page+page_size,page_size,PROT_NONE)) return 1;
#endif
    csh fast{}, slow{};
    if (cs_open(CS_ARCH_X86,CS_MODE_32,&fast) || cs_open(CS_ARCH_X86,CS_MODE_32,&slow)) return 2;
    cs_opt_mnem custom{X86_INS_UD2,"unused-ud2"};
    if (cs_option(slow,CS_OPT_MNEMONIC,(uintptr_t)&custom)) return 3;
    uint64_t checked=0, decoded=0, hash=0xcbf29ce484222325;
    for (auto detail : {CS_OPT_OFF,CS_OPT_ON}) {
        if(cs_option(fast,CS_OPT_DETAIL,detail)||cs_option(slow,CS_OPT_DETAIL,detail))return 4;
        for (unsigned prefix : {0x26,0x2e,0x36,0x3e,0x64,0x65}) for(unsigned op : {0x2b,0x89,0x8b,0x8d}) {
            for(unsigned mr=0;mr<256;++mr)for(unsigned pattern=0;pattern<8;++pattern) {
                static const uint32_t disp[]={0,9,10,0x7f,0xffffffe0,0x80000000,0x12345678,0xffffffff};
                const bool sib=(mr&7)==4 && mr<0xc0;
                static const uint8_t sibs[]={0x00,0x04,0x05,0x24,0x25,0x9a,0xd6,0xff};
                uint8_t bytes[]={uint8_t(prefix),uint8_t(op),uint8_t(mr),0,0,0,0,0};
                if(sib)bytes[3]=sibs[pattern];
                uint32_t value=disp[pattern];
                for(unsigned k=0;k<4;++k)bytes[3+unsigned(sib)+k]=uint8_t(value>>(k*8));
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
    cs_close(&fast);cs_close(&slow);
#ifdef _WIN32
    VirtualFree(page,0,MEM_RELEASE);
#else
    munmap(page,page_size*2);
#endif
    printf("%" PRIu64 " %" PRIu64 " %" PRIu64 "\n",checked,decoded,hash);
}
