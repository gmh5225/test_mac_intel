#include <capstone/capstone.h>
#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iterator>
#include <vector>

struct Span { size_t off, size; uint64_t ip; };
int main(int argc, char **argv) {
    if (argc != 7) return 2;
    std::ifstream input(argv[1],std::ios::binary), ranges(argv[2]);
    std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(input),{}};
    std::vector<Span> spans;
    Span span;
    while(ranges >> span.off >> span.size >> span.ip) {
        if (!span.size || span.off > bytes.size() || span.size > bytes.size()-span.off) return 3;
        spans.push_back(span);
    }
    if (!ranges.eof() || spans.empty()) return 3;
    const int bits=std::atoi(argv[3]), att=std::atoi(argv[4]), detail=std::atoi(argv[5]), reps=std::atoi(argv[6]);
    csh h;
    if (reps<=0 || cs_open(CS_ARCH_X86,bits==32?CS_MODE_32:CS_MODE_64,&h) ||
        cs_option(h,CS_OPT_SYNTAX,att?CS_OPT_SYNTAX_ATT:CS_OPT_SYNTAX_INTEL) ||
        cs_option(h,CS_OPT_DETAIL,detail?CS_OPT_ON:CS_OPT_OFF)) return 4;
    cs_insn *insn=cs_malloc(h); if (!insn) return 5;
    uint64_t accepted=0,rejected=0,value=0,boundary=0;
    auto pass = [&] {
        for (auto f : spans) {
            const uint8_t *p=bytes.data()+f.off;
            while (f.size) {
                if (!cs_disasm_iter(h,&p,&f.size,&f.ip,insn)) {++rejected;++p;--f.size;++f.ip;continue;}
                ++accepted;boundary=boundary*131+insn->id+insn->address+insn->size;
                value+=std::strlen(insn->mnemonic)+std::strlen(insn->op_str);
                if (detail) {
                    cs_regs rr,rw;uint8_t nr,nw;
                    if(cs_regs_access(h,insn,rr,&nr,rw,&nw)) std::abort();
                    for(unsigned i=0;i<nr;++i)value+=rr[i];
                    for(unsigned i=0;i<nw;++i)value+=rw[i];
                    value+=insn->detail->x86.op_count+insn->detail->x86.eflags;
                }
            }
        }
    };
    pass();accepted=rejected=value=boundary=0;
    const auto begin=std::chrono::steady_clock::now();const auto before=std::clock();
    for (int i=0;i<reps;++i) pass();
    uint64_t cpu=uint64_t(double(std::clock()-before)*1e9/CLOCKS_PER_SEC);
    auto wall=std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now()-begin).count();
    std::printf("%" PRIu64 " %lld %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",cpu,(long long)wall,accepted,rejected,boundary,value);
    cs_free(insn,1);cs_close(&h);
    return 0;
}
