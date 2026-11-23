#include <capstone/capstone.h>
#include <array>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <vector>
extern "C" bool observed_bare(const uint8_t *, size_t, bool);
int main(int argc,char **argv)
{
    if (argc!=3 && argc!=4) return 1;
    bool wide=argv[1][0]=='6';
    std::ifstream f(argv[2],std::ios::binary);
    std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(f),{}};
    if (bytes.empty()) return 2;
    std::vector<std::array<uint64_t,3>> spans;
    if(argc==4) {
        std::ifstream list(argv[3]);
        uint64_t offset,size,ip;
        while (list>>offset>>size>>ip) spans.push_back({offset,size,ip});
        if(!list.eof() || spans.empty()) return 3;
    } else spans.push_back({0,bytes.size(),0});
    csh h=0;
    cs_opt_mnem custom{X86_INS_UD2,"ud2"};
    if(cs_open(CS_ARCH_X86,wide?CS_MODE_64:CS_MODE_32,&h) ||
       cs_option(h,CS_OPT_MNEMONIC,reinterpret_cast<uintptr_t>(&custom))) return 4;
    cs_insn x{};
    unsigned long long valid=0,miss=0,hits=0;std::array<unsigned long long,256> ops{};
    for(auto [start,length,ip] : spans) {
        if(start>bytes.size() || length>bytes.size()-start) return 5;
        const uint8_t *p=bytes.data()+start;size_t size=static_cast<size_t>(length);
        while(size) {
            auto *begin=p;
            if(!cs_disasm_iter(h,&p,&size,&ip,&x)) { ++p; --size; ++ip; ++miss; continue; }
            ++valid;
            if (observed_bare(begin,x.size,wide)) {
                const unsigned prefix=begin[0]==0xc5?2:3;
                ++ops[begin[prefix]];
                ++hits;
            }
        }
    }
    cs_close(&h);
    std::printf("%llu %llu %llu",valid,miss,hits);
    for (auto count:ops) std::printf(" %llu",count);
    std::putchar('\n');
    return 0;
}
