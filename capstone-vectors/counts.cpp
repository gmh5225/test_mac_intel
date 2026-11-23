#include <capstone/capstone.h>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <vector>
extern "C" bool X86_disasmIter32(csh, const uint8_t **, size_t *, uint64_t *, cs_insn *);
extern "C" bool X86_disasmIterText(csh, const uint8_t **, size_t *, uint64_t *, cs_insn *);
extern "C" unsigned long long helper_calls, bare_opcode_hits[256];
int main(int argc,char **argv) {
    if(argc!=4) return 1;
    const bool wide=argv[1][0]=='6';
    std::ifstream binary(argv[2],std::ios::binary),spans(argv[3]);
    if(!binary || !spans) return 2;
    const std::vector<uint8_t> text{std::istreambuf_iterator<char>(binary),{}};
    csh h;
    if(cs_open(CS_ARCH_X86,wide?CS_MODE_64:CS_MODE_32,&h))return 3;
    cs_insn *insn=cs_malloc(h);
    if(!insn)return 4;
    unsigned long long records=0, invalid=0;
    size_t offset,len;
    uint64_t ip;
    auto next=wide?X86_disasmIterText:X86_disasmIter32;
    while(spans>>offset>>len>>ip) {
        if(offset>text.size() || len>text.size()-offset)return 5;
        const uint8_t *cursor=text.data()+offset;
        while (len) {
            const uint8_t *start=cursor;
            const size_t available=len;
            const uint64_t address=ip;
            if (next(h,&cursor,&len,&ip,insn)) {
                ++records;
            } else {
                cursor=start+1;
                len=available-1;
                ip=address+1;
                ++invalid;
            }
        }
    }
    cs_free(insn,1);
    if(cs_close(&h) || !records)return 6;
    std::printf("%llu %llu %llu %llu %llu\n",records,helper_calls,bare_opcode_hits[0xa4],bare_opcode_hits[0xac],invalid);
}
