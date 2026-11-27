#include <capstone/capstone.h>
#include "arch/X86/X86ScanAdapter.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <map>
#include <string>
#include <vector>
extern "C" { uint64_t cap_profile[5] = {}; }
int main(int argc, char **argv) {
    if (argc != 7) return 2;
    std::ifstream source(argv[1], std::ios::binary), spans(argv[2]);
    std::vector<uint8_t> bytes(std::istreambuf_iterator<char>(source), {});
    if (bytes.empty() || !spans) return 3;
    csh h;
    if (cs_open(CS_ARCH_X86, std::atoi(argv[3]) == 32 ? CS_MODE_32 : CS_MODE_64, &h)) return 4;
    if (cs_option(h, CS_OPT_DETAIL, std::atoi(argv[4]) ? CS_OPT_ON : CS_OPT_OFF)) return 5;
    if(cs_option(h, CS_OPT_SYNTAX, std::atoi(argv[6]) ? CS_OPT_SYNTAX_ATT : CS_OPT_SYNTAX_INTEL))return 11;
    auto next=std::atoi(argv[5]) ? cs_disasm_iter : X86_disasmIterText;
    cs_insn *record = cs_malloc(h);
    size_t off, n, ok=0, bad=0, length=0; uint64_t addr;
    uint64_t digest=14695981039346656037ULL;
    auto add=[&](const void *p,size_t n){for(auto v=static_cast<const unsigned char *>(p);n--;++v)digest=(digest^*v)*1099511628211ULL;};
    std::map<std::string,std::array<size_t,4>> counts;
    while (spans >> off >> n >> addr) {
        if (off > bytes.size() || n > bytes.size()-off || !n) return 6;
        auto *p=static_cast<const uint8_t *>(bytes.data()+off);length+=n;
        while (n) {
            auto *old=p;
            if (!next(h,&p,&n,&addr,record)) {++p; --n; ++addr; ++bad; continue;}
            if (p-old!=record->size || !record->size) return 7;
            ++ok;add(&record->address,sizeof record->address);add(&record->size,sizeof record->size);add(&record->id,sizeof record->id);
            add(record->bytes,record->size);add(record->mnemonic,std::strlen(record->mnemonic)+1);add(record->op_str,std::strlen(record->op_str)+1);
            if (record->detail) {
                cs_regs reads,writes;uint8_t nread,nwrite;
                if(cs_regs_access(h,record,reads,&nread,writes,&nwrite)!=CS_ERR_OK)return 9;
                add(&nread,1);add(reads,nread*sizeof(reads[0]));add(&nwrite,1);add(writes,nwrite*sizeof(writes[0]));
            }
        }
    }
    std::printf("%zu %zu %zu %llu",ok,bad,length,(unsigned long long)digest);
    for(auto value : cap_profile) std::printf(" %llu",(unsigned long long)value);
    std::puts("");cs_free(record,1);cs_close(&h);return 0;
}
