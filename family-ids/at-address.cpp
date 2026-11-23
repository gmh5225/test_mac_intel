#include "arch/X86/X86ScanAdapter.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <random>
#include <time.h>
#include <vector>

extern "C" size_t X86_disasmOneText(csh, const uint8_t *, size_t, uint64_t, cs_insn *);
static uint64_t tick(clockid_t id) {
    timespec t;
    if (clock_gettime(id, &t)) std::abort();
    return uint64_t(t.tv_sec)*1000000000 + t.tv_nsec;
}

struct Input {
    uint64_t address;
    std::vector<uint8_t> bytes;
    std::vector<size_t> starts;
};
template <int Entry> bool decode(csh h,const uint8_t *code,size_t length,uint64_t address,cs_insn *insn) {
    insn->illegal = false;
    if constexpr (Entry == 0) return X86_disasmIterText(h, &code, &length, &address, insn);
    if constexpr (Entry == 1) return X86_disasmOneText(h, code, length, address, insn) != 0;
    return X86_decodeOneText(h, code, length, address, insn);
}

template <int Entry> static uint64_t visit(const Input& input, csh handle,cs_insn *insn,bool detail) {
    uint64_t sum=0;
    for(size_t at : input.starts) {
        const bool ok=decode<Entry>(handle,input.bytes.data()+at,input.bytes.size()-at,input.address+at,insn);
        if(!ok)std::abort();
        sum+=insn->id+insn->size+std::strlen(insn->mnemonic)+std::strlen(insn->op_str);
        if(detail) {
            cs_regs read,written;uint8_t nr,nw;
            if(cs_regs_access(handle,insn,read,&nr,written,&nw))std::abort();
            sum+=insn->detail->x86.eflags+nr+nw;
        }
    }
    return sum;
}

static bool equal_at(csh h, const Input& input, size_t at, bool detail) {
    cs_insn results[3]{};cs_detail details[3];bool ok[3];
    auto p=input.bytes.data()+at;size_t n=input.bytes.size()-at;auto ip=input.address+at;
    for(unsigned i=0;i<3;++i) {
        std::memset(details+i,(at&1)?0xa5:0,sizeof(details[i]));
        results[i].detail=detail? details+i:nullptr;
    }
    ok[0]=decode<0>(h,p,n,ip,results);
    ok[1]=decode<1>(h,p,n,ip,results+1);
    ok[2]=decode<2>(h,p,n,ip,results+2);
    for(unsigned i=0;i<3;++i) {
        if(results[i].detail!=(detail?details+i:nullptr))std::abort();
        results[i].detail=nullptr;
        if(ok[i]!=ok[0] || std::memcmp(results,results+i,sizeof(results[i])) ||
           std::memcmp(details,details+i,sizeof(details[i])))std::abort();
    }
    return ok[0];
}

int main(int argc,char **argv) {
    if(argc!=5)return 2;
    int bits=std::atoi(argv[2]);bool detail=std::atoi(argv[3])==2;
    std::ifstream file(argv[1],std::ios::binary);Input input{std::strtoull(argv[4],nullptr,10),
        std::vector<uint8_t>{std::istreambuf_iterator<char>(file),{}},{}};
    if(input.bytes.empty())return 3;
    csh h;
    if(cs_open(CS_ARCH_X86,bits==32?CS_MODE_32:CS_MODE_64,&h) ||
       cs_option(h,CS_OPT_DETAIL,detail?CS_OPT_ON:CS_OPT_OFF))return 4;
    auto insn=cs_malloc(h);
    if(!insn)return 5;
    for(size_t pos=0;pos<input.bytes.size();) {
        const bool matched=equal_at(h,input,pos,detail);
        if(!matched){++pos;continue;}
        const uint8_t *p=input.bytes.data()+pos;size_t left=input.bytes.size()-pos;uint64_t addr=input.address+pos;
        if(!X86_disasmIterText(h,&p,&left,&addr,insn) || !insn->size)std::abort();
        input.starts.push_back(pos);pos+=insn->size;
    }
    const std::array<decltype(&visit<0>),4> go{visit<0>,visit<1>,visit<2>,visit<0>};
    const auto first=tick(CLOCK_PROCESS_CPUTIME_ID);const auto expected=go[0](input,h,insn,detail);
    const auto reps=std::clamp<uint64_t>(25000000/std::max<uint64_t>(1,tick(CLOCK_PROCESS_CPUTIME_ID)-first),1,100);
    for(auto fn:go)if(fn(input,h,insn,detail)!=expected)return 6;
    std::array<unsigned,4> order{0,1,2,3};std::mt19937 gen(2305+bits+detail);
    std::printf("{\"records\":%zu,\"sum\":%llu,\"reps\":%llu,\"cycles\":[",input.starts.size(),(unsigned long long)expected,(unsigned long long)reps);
    for(unsigned n=0;n<21;++n) {
        std::shuffle(order.begin(),order.end(),gen);uint64_t cpu[4]{},wall[4]{};
        for(unsigned i=0;i<8;++i) {
            const auto k=order[i<4?i:7-i];const auto fn=go[k];
            const auto c=tick(CLOCK_PROCESS_CPUTIME_ID),w=tick(CLOCK_MONOTONIC);uint64_t x=0;
            for(uint64_t j=0;j<reps;++j)x+=fn(input,h,insn,detail);
            wall[k]+=tick(CLOCK_MONOTONIC)-w;cpu[k]+=tick(CLOCK_PROCESS_CPUTIME_ID)-c;
            if(x!=expected*reps)return 7;
        }
        std::printf("%s[",n?",":"");
        for(unsigned i=0;i<4;++i)std::printf("%s[%llu,%llu]",i?",":"",(unsigned long long)cpu[i],(unsigned long long)wall[i]);
        std::printf("]");
    }
    std::puts("]}");cs_free(insn,1);cs_close(&h);
}
