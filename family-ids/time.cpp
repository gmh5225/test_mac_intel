#include "arch/X86/X86ScanAdapter.h"
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <random>
#include <time.h>
#include <vector>
extern "C" void bench_select_prefix(unsigned merged);
static uint64_t now(clockid_t c) { timespec t{}; if(clock_gettime(c, &t)) std::abort(); return uint64_t(t.tv_sec)*1000000000+t.tv_nsec; }
template<bool Private> static uint64_t consume(csh h,cs_insn *i,const std::vector<uint8_t>& bytes,uint64_t addr,int mode) {
    auto *p=bytes.data(); auto left=bytes.size(); uint64_t hash=0;
    while(left) {
        const bool ok=Private ? X86_disasmIterText(h,&p,&left,&addr,i) : cs_disasm_iter(h,&p,&left,&addr,i);
        if(!ok){++p;--left;++addr; continue;}
        hash+=i->id+i->size;
        if(mode){hash+=std::strlen(i->mnemonic)+std::strlen(i->op_str);}
        if(mode==2){uint8_t nr=0,nw=0;cs_regs read,written;if(cs_regs_access(h,i,read,&nr,written,&nw))std::abort();hash+=i->detail->x86.eflags+nr+nw;}
    }
    return hash;
}
int main(int argc,char **argv) {
    if(argc!=6)return 2;
    int bits=std::atoi(argv[2]),mode=std::atoi(argv[3]);bool priv=std::atoi(argv[4])!=0;
    uint64_t addr=std::strtoull(argv[5],nullptr,10);std::ifstream s(argv[1],std::ios::binary);
    std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(s),{}};if(bytes.empty())return 3;
    csh h;if(cs_open(CS_ARCH_X86,bits==32?CS_MODE_32:CS_MODE_64,&h))return 4;
    cs_option(h,CS_OPT_TEXT,mode?CS_OPT_ON:CS_OPT_OFF);cs_option(h,CS_OPT_DETAIL,mode==2?CS_OPT_ON:CS_OPT_OFF);auto *insn=cs_malloc(h);if(!insn)return 5;
    auto go=priv?consume<true>:consume<false>;
    uint64_t a=now(CLOCK_PROCESS_CPUTIME_ID);auto expected=go(h,insn,bytes,addr,mode);
    unsigned reps=unsigned(std::min<uint64_t>(100,std::max<uint64_t>(1,27000000/std::max<uint64_t>(1,now(CLOCK_PROCESS_CPUTIME_ID)-a))));
    for(unsigned n=0;n<4;++n){bench_select_prefix(n&1);if(go(h,insn,bytes,addr,mode)!=expected)return 6;}
    std::array<int,4> keys{0,1,2,3};std::mt19937 rng(2300+bits+mode+priv);
    std::printf("{\"sum\":%llu,\"reps\":%u,\"cycles\":[",static_cast<unsigned long long>(expected),reps);
    for(unsigned cycle=0;cycle<21;++cycle){
        std::shuffle(keys.begin(),keys.end(),rng); uint64_t cpu[4]{},wall[4]{};
        for(unsigned n=0;n<8;++n){
            int key=keys[n<4?n:7-n];bench_select_prefix(key&1);
            uint64_t c=now(CLOCK_PROCESS_CPUTIME_ID),t=now(CLOCK_MONOTONIC),x=0;
            for(unsigned j=0;j<reps;++j)x+=go(h,insn,bytes,addr,mode);
            wall[key]+=now(CLOCK_MONOTONIC)-t;cpu[key]+=now(CLOCK_PROCESS_CPUTIME_ID)-c;if(x!=expected*reps)return 7;
        }
        std::printf("%s[",cycle?",":"");
        for(unsigned k=0;k<4;++k)std::printf("%s[%llu,%llu]",k?",":"",(unsigned long long)cpu[k],(unsigned long long)wall[k]);
        std::printf("]");
    }
    std::puts("]}");cs_free(insn,1);cs_close(&h);
}
