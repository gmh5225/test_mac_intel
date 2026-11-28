#include <capstone/capstone.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <vector>
#include "arch/X86/X86ScanAdapter.h"
extern "C" { unsigned seen_general = 0; }
int main(int argc,char **argv) {
    if(argc!=6 || (argv[5][0]!='1' && argv[5][0]!='2'))return 1;
    std::ifstream file(argv[2],std::ios::binary),spans(argv[3]);std::ofstream output(argv[4],std::ios::binary);
    if(!file||!spans||!output)return 2;
    std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(file),{}};
    csh h;if(cs_open(CS_ARCH_X86,argv[1][0]=='3'?CS_MODE_32:CS_MODE_64,&h) || cs_option(h,CS_OPT_DETAIL,argv[5][0]=='2'?CS_OPT_ON:CS_OPT_OFF))return 3;
    auto rec=cs_malloc(h);if(!rec)return 4;
    size_t offset,left;uint64_t ip,counts[3]{};
    while(spans>>offset>>left>>ip) {
        if(offset>bytes.size()||left>bytes.size()-offset)return 5;
        auto pc=static_cast<const uint8_t *>(bytes.data()+offset);
        while(left) {
            const uint64_t at=static_cast<uint64_t>(pc-bytes.data());
            seen_general=0;
            const bool ok=X86_disasmIterText(h,&pc,&left,&ip,rec);
            if(seen_general>1)return 7;
            const uint8_t kind=ok ? (seen_general ? 2 : 1) : 0;
            if(!ok){++pc;--left;++ip;}
            output.write(reinterpret_cast<const char *>(&at),sizeof(at));output.put(char(kind));++counts[kind];
        }
    }
    if(!spans.eof() || !output)return 6;
    for(auto n:counts)std::printf("%llu ",(unsigned long long)n);
    std::puts("");cs_free(rec,1);return cs_close(&h)!=CS_ERR_OK;
}
