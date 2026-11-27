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
extern "C" { unsigned cap_profile[3] = {}; }
int main(int argc, char **argv) {
    if (argc != 7) return 2;
    std::ifstream source(argv[1], std::ios::binary), spans(argv[2]);
    std::vector<uint8_t> bytes(std::istreambuf_iterator<char>(source), {});
    if (bytes.empty() || !spans) return 3;
    csh h;
    if (cs_open(CS_ARCH_X86, std::atoi(argv[3]) == 32 ? CS_MODE_32 : CS_MODE_64, &h)) return 4;
    if (cs_option(h, CS_OPT_DETAIL, std::atoi(argv[4]) ? CS_OPT_ON : CS_OPT_OFF)) return 5;
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
            auto *old=p;std::fill_n(cap_profile,3,0U);
            if (!next(h,&p,&n,&addr,record)) {++p; --n; ++addr; ++bad; continue;}
            if (p-old!=record->size || !record->size) return 7;
            ++ok;add(&record->address,sizeof record->address);add(&record->size,sizeof record->size);add(&record->id,sizeof record->id);
            add(record->bytes,record->size);add(record->mnemonic,std::strlen(record->mnemonic)+1);add(record->op_str,std::strlen(record->op_str)+1);
            if (record->detail) {
                cs_regs reads,writes;uint8_t nread,nwrite;
                if(cs_regs_access(h,record,reads,&nread,writes,&nwrite)!=CS_ERR_OK)return 9;
                add(&nread,1);add(reads,nread*sizeof(reads[0]));add(&nwrite,1);add(writes,nwrite*sizeof(writes[0]));
            }
            const bool vec=old[0]==0xc4 || old[0]==0xc5 || old[0]==0x62;
            unsigned prefix=old[0]==0xc4?3:old[0]==0xc5?2:4;
            char key[128];
            if (vec && record->size>prefix+1) {
                unsigned mr=old[prefix+1];const char *shape=mr>=0xc0?"reg":(mr&7)==4?"sib":(mr&0xc7)==5?"rip":"base";
                std::snprintf(key,sizeof key,"%s/%02x/%s",record->mnemonic,old[0],shape);
            } else if (record->detail) {
                const auto &x=record->detail->x86;
                const unsigned mr=x.modrm;
                const char *address=x.encoding.modrm_offset==0?"implicit":mr>=0xc0?"reg":(mr&7)==4?"sib":
                    (mr&0xc7)==5?(x.addr_size==8?"rip":"absolute"):"base";
                unsigned flags=0;
                for (unsigned j=0;j<4;++j) if (x.prefix[j]) flags|=1u<<j;
                std::snprintf(key,sizeof key,"%s/%02x%02x%02x%02x/p%x/w%u/%s/d%ui%u/t%u.%u",
                    record->mnemonic,x.opcode[0],x.opcode[1],x.opcode[2],x.opcode[3],flags,
                    unsigned((x.rex>>3)&1),address,x.encoding.disp_size,x.encoding.imm_size,
                    unsigned(x.op_count?x.operands[0].type:0),unsigned(x.op_count>1?x.operands[1].type:0));
            } else std::snprintf(key,sizeof key,"%s",record->mnemonic);
            auto &c=counts[key];++c[0];for(unsigned i=0;i<3;++i)c[1+i]+=cap_profile[i];
        }
    }
    std::ofstream log(argv[6]);if(!log)return 8;
    for (const auto &kv:counts) {log<<kv.first;for(auto v:kv.second)log<<"\t"<<v;log<<"\n";}
    std::printf("%zu %zu %zu %llu\n",ok,bad,length,(unsigned long long)digest);cs_free(record,1);cs_close(&h);
    return 0;
}
