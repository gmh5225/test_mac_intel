#include <capstone/capstone.h>
#include "arch/X86/X86ScanAdapter.h"
#include <array>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iterator>
#include <vector>

extern "C" void bench_select(unsigned);
extern "C" uint64_t bench_count();
extern "C" unsigned capstone_bench_access_count();
extern "C" int capstone_bench_access(csh, unsigned, uint64_t *, uint8_t *);

struct Span { size_t start, size; uint64_t ip; };
uint64_t clock_ns(clockid_t clock) {
    timespec t{};
    if(clock_gettime(clock, &t)) std::abort();
    return uint64_t(t.tv_sec)*1000000000+t.tv_nsec;
}
int verify(){
    unsigned count=capstone_bench_access_count(), total=0;
    for(auto mode:{CS_MODE_16,CS_MODE_32,CS_MODE_64}){
        csh h{}; if(cs_open(CS_ARCH_X86,mode,&h))return 2;
        for(bool cached:{false,true})for(unsigned n=0;n<count+3;++n){
            const unsigned id=n==count+2?UINT32_MAX:n;std::array<unsigned char,6>a,b;a.fill(0xa5);b=a;
            uint64_t x=UINT64_C(0xddd000eeefff0001),y=x;
            bench_select(0);auto left=capstone_bench_access(cached?h:0,id,&x,a.data());
            bench_select(2);auto right=capstone_bench_access(cached?h:0,id,&y,b.data());
            if(left!=right||a!=b||x!=y)return 3;
            ++total;
        }
        cs_close(&h);
    }
    std::printf("%u %u\n",count,total);return 0;
}
template <auto Next>
std::array<uint64_t,2> walk(csh h,cs_insn *i,const std::vector<uint8_t>&text,
                            const std::vector<Span>&spans,bool detail){
    uint64_t count=0, signature=0;
    for(const auto &s:spans){
        auto p=text.data()+s.start; auto n=s.size;auto ip=s.ip;
        while(n){
            if(Next(h,&p,&n,&ip,i)){
                ++count;signature+=i->id+i->size+uint8_t(i->mnemonic[0])+uint8_t(i->op_str[0]);
                if(detail) signature+=i->detail->x86.op_count;
            }else{++p;--n;++ip;}
        }
    }
    return {count,signature};
}
int main(int argc,char **v){
    if(argc==2 && !std::strcmp(v[1],"verify"))return verify();
    if(argc!=8)return 2;
    const unsigned choice=std::strtoul(v[1],nullptr,10),route=std::strtoul(v[2],nullptr,10),detail=std::strtoul(v[3],nullptr,10);
    std::ifstream raw(v[4],std::ios::binary), map(v[5]); if(!raw||!map)return 2;
    std::vector<uint8_t> text{std::istreambuf_iterator<char>(raw),{}};std::vector<Span> spans;Span s;
    while(map>>s.start>>s.size>>s.ip){
        if(!s.size||s.start>text.size()||s.size>text.size()-s.start)return 3;
        spans.push_back(s);
    }
    const int bits=std::atoi(v[6]), reps=std::atoi(v[7]);
    if(spans.empty()||reps<=0||choice>4||route>1||detail>1)return 4;
    csh h{};if(cs_open(CS_ARCH_X86,bits==64?CS_MODE_64:CS_MODE_32,&h)||cs_option(h,CS_OPT_DETAIL,detail?CS_OPT_ON:CS_OPT_OFF))return 5;
    auto i=cs_malloc(h);if(!i)return 5;
    auto entry=route?walk<X86_disasmIter>:walk<cs_disasm_iter>;
    bench_select(choice);auto reference=entry(h,i,text,spans,detail);
    bench_select(choice);const uint64_t a=clock_ns(CLOCK_PROCESS_CPUTIME_ID),b=clock_ns(CLOCK_MONOTONIC);
    uint64_t result=0;
    for(int n=0;n<reps;++n){auto row=entry(h,i,text,spans,detail);result+=row[0]+row[1];}
    auto wall=clock_ns(CLOCK_MONOTONIC)-b,cpu=clock_ns(CLOCK_PROCESS_CPUTIME_ID)-a;
    if(result!=(reference[0]+reference[1])*reps)return 6;
    std::printf("%" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",cpu,wall,reference[0],reference[1],bench_count());
    cs_free(i,1);cs_close(&h);
}
