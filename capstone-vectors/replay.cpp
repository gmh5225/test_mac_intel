#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>
#include <time.h>

namespace arithmetic {
#include "baseline.h"
}
#undef CS_X86_VECTOR_REGISTER_WRITER_H
#define CAPSTONE_INTERNAL
namespace padded {
#include "candidate.h"
#include "table.inc"
}

struct Event { uint8_t offset,bank,number,flags; int advance; };
using Buffer=std::array<char,160>;
template<int K> static inline char *put(char *dst,const Event &op) {
    const bool joined=op.flags & 1;
    if constexpr(K==2) {
        return joined?padded::appendVectorRegister(dst,op.bank,op.number)
                     :padded::writeVectorRegister(dst,op.bank,op.number);
    }
    if(joined){std::memcpy(dst,", ",2);dst+=2;}
    if constexpr(K==1)return padded::writeVectorRegister(dst,op.bank,op.number);
    return arithmetic::writeVectorRegister(dst,op.bank,op.number);
}
static bool verify(const std::vector<Event> &events) {
    Buffer a{},b{},c{};
    for(const auto &ev:events){
        if(ev.flags&2){
            if(a!=b||a!=c)return false;
            a.fill(0);b.fill(0);c.fill(0);
        }
        const unsigned end=ev.offset+4+(ev.number>=10)+2*(ev.flags&1);
        if(put<0>(a.data()+ev.offset,ev)!=a.data()+end ||
           put<1>(b.data()+ev.offset,ev)!=b.data()+end ||
           put<2>(c.data()+ev.offset,ev)!=c.data()+end)return false;
    }
    return a==b && a==c;
}
template<int K> __attribute__((noinline)) static uint64_t render(const std::vector<Event> &events,unsigned repeats) {
    Buffer out{};uint64_t sum=0;
    for(unsigned i=0;i!=repeats;++i) {
        char *next=out.data();
        for(const auto &op:events) {
            if(op.flags&2) {
                asm volatile("" : : "r"(out.data()) : "memory");
                next=out.data()+op.offset;
            } else {
                next+=op.advance;
            }
            next=put<K>(next,op);
        }
        asm volatile("" : : "r"(out.data()) : "memory");
        sum+=uint64_t(next-out.data());
    }
    return sum;
}
static uint64_t cpu(){
    timespec t{};if(clock_gettime(CLOCK_PROCESS_CPUTIME_ID,&t))std::abort();
    return uint64_t(t.tv_sec)*1000000000+t.tv_nsec;
}
int main(int argc,char **argv) {
    if(argc!=4)return 1;
    std::ifstream input(argv[1],std::ios::binary);
    if(!input)return 2;
    std::vector<uint8_t> raw{std::istreambuf_iterator<char>(input),{}};
    if(raw.size()%4)return 3;
    std::vector<Event> events;int pos=0;
    for(size_t j=0;j<raw.size();j+=4){
        Event e{raw[j],raw[j+1],raw[j+2],raw[j+3],int(raw[j])-pos};
        if(e.flags>3||e.bank>=3||e.number>=32||(!j && !(e.flags&2))||
           e.offset+((e.flags&1)?8u:6u)>Buffer{}.size())return 4;
        pos=e.offset+4+(e.number>=10)+2*(e.flags&1);events.push_back(e);
    }
    const std::string key=argv[2];
    if(key=="test")return verify(events)?0:5;
    const unsigned repeat=std::stoul(argv[3]);
    auto fn=key=="base"||key=="copy"?render<0>:key=="rows"?render<1>:key=="fuse"?render<2>:nullptr;
    if(!fn||!repeat||!events.size())return 6;
    uint64_t warm=fn(events,1);
    auto t0=std::chrono::steady_clock::now();auto c0=cpu();
    const uint64_t check=fn(events,repeat);
    auto c1=cpu();auto t1=std::chrono::steady_clock::now();
    if(check!=warm*repeat)return 7;
    auto ns=std::chrono::duration_cast<std::chrono::nanoseconds>(t1-t0).count();
    std::printf("%llu %lld %llu\n",(unsigned long long)(c1-c0),(long long)ns,(unsigned long long)check);
}
