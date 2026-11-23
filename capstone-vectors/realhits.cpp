#include <capstone/capstone.h>
#include <array>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <vector>
extern "C" bool X86_disasmIter32(csh,const uint8_t **,size_t *,uint64_t *,cs_insn *);
extern "C" bool X86_disasmIterText(csh,const uint8_t **,size_t *,uint64_t *,cs_insn *);
extern "C" unsigned long long bare_opcode_hits[256];
int main(int argc, char **argv) {
    if (argc!=6) return 1;
    const bool wide=argv[1][0]=='6', private_reader=argv[2][0]=='1', detail=argv[3][0]=='1';
    std::ifstream input(argv[4],std::ios::binary), ranges(argv[5]);
    std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(input),{}};
    csh handle=0;
    if (bytes.empty() || !ranges || cs_open(CS_ARCH_X86,wide?CS_MODE_64:CS_MODE_32,&handle) ||
        cs_option(handle,CS_OPT_DETAIL,detail?CS_OPT_ON:CS_OPT_OFF)) return 2;
    cs_insn *out=cs_malloc(handle); if(!out) return 3;
    auto next=private_reader?(wide?X86_disasmIterText:X86_disasmIter32):cs_disasm_iter;
    size_t offset,length;uint64_t address,ok=0,invalid=0;unsigned spans=0;
    while(ranges>>offset>>length>>address) {
        if (offset>bytes.size() || length>bytes.size()-offset) return 4;
        const auto *p=bytes.data()+offset;
        while(length) {
            if(next(handle,&p,&length,&address,out)) ++ok;
            else { ++p; --length; ++address; ++invalid; }
        }
        ++spans;
    }
    if(!ranges.eof() || !spans || !ok) return 5;
    std::printf("%llu %llu %u",static_cast<unsigned long long>(ok),static_cast<unsigned long long>(invalid),spans);
    for(auto n:bare_opcode_hits) std::printf(" %llu",n);
    std::putchar('\n');cs_free(out,1);cs_close(&handle);
}
