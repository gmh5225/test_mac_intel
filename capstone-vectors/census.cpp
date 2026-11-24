#include <capstone/capstone.h>
#include "arch/X86/X86ScanAdapter.h"
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <string>
#include <utility>
#include <vector>

extern "C" uint64_t profile_full_decodes;
using Next = decltype(&cs_disasm_iter);

struct Reader {
    csh handle{};
    cs_insn *out{};
    Next step{};
};

int main(int argc, char **argv) {
    if (argc != 5) return 1;
    std::ifstream input(argv[1], std::ios::binary), extents(argv[2]);
    const std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(input), {}};
    if (bytes.empty() || !extents) return 2;
    const cs_mode mode = std::atoi(argv[3]) == 64 ? CS_MODE_64 : CS_MODE_32;
    std::array<Reader,4> readers{};
    for (size_t i = 0; i < readers.size(); ++i) {
        Reader &r = readers[i];
        if (cs_open(CS_ARCH_X86,mode,&r.handle)) return 3;
        if (cs_option(r.handle,CS_OPT_DETAIL,(i & 1) ? CS_OPT_ON : CS_OPT_OFF)) return 3;
        r.out = cs_malloc(r.handle);
        if (!r.out) return 3;
        r.step = i < 2 ? cs_disasm_iter : X86_disasmIterText;
    }
    using Outcome = std::array<uint64_t,5>;
    struct Family { Outcome count{}; std::map<std::string, unsigned> encodings; };
    std::map<std::pair<std::string,std::string>,Family> families;
    std::array<uint64_t,4> misses{};
    uint64_t accepted = 0, rejected = 0, consumed = 0, digest = 0;
    std::vector<uint8_t> route;
    size_t begin, length;
    uint64_t address;
    while (extents >> begin >> length >> address) {
        if (begin > bytes.size() || length > bytes.size()-begin || !length) return 4;
        const size_t tag=route.size();route.resize(tag+length,255);
        size_t offset = 0;
        while (offset < length) {
            unsigned valid = 0;
            std::array<unsigned,4> fallback{};
            for (unsigned i=0; i<readers.size(); ++i) {
                auto &r = readers[i];
                const auto *start = &bytes[begin+offset], *ptr = start;
                size_t left = length-offset;
                uint64_t ip = address+offset, before = profile_full_decodes;
                bool ok = r.step(r.handle,&ptr,&left,&ip,r.out);
                fallback[i] = unsigned(profile_full_decodes-before);
                if (fallback[i] > 1 || (ok && (r.out->size != ptr-start ||
                    left+r.out->size != length-offset || ip != address+offset+r.out->size))) return 5;
                if (ok) {
                    ++valid;
                    const auto *first = readers[0].out;
                    if (i && (r.out->id != first->id || r.out->address != first->address ||
                        r.out->size != first->size || std::strcmp(r.out->mnemonic,first->mnemonic) ||
                        std::strcmp(r.out->op_str,first->op_str))) return 6;
                }
            }
            route[tag+offset]=uint8_t(fallback[2] | (fallback[3]<<1) | (!valid<<2));
            if (!valid) {
                for (unsigned i=0; i<readers.size(); ++i) misses[i] += fallback[i];
                ++offset; ++rejected; ++consumed; continue;
            }
            if (valid != readers.size()) return 7;
            const auto &x=readers[1].out->detail->x86, &y=readers[3].out->detail->x86;
            if(x.op_count != y.op_count || x.eflags != y.eflags || std::memcmp(&x.encoding,&y.encoding,sizeof(x.encoding))) return 8;
            std::string form, head;
            for (unsigned j=0; j<x.op_count; ++j) {
                const auto &a=x.operands[j], &b=y.operands[j];
                if(a.type!=b.type || a.size!=b.size || a.access!=b.access) return 8;
                form += a.type==X86_OP_REG ? 'R' : a.type==X86_OP_MEM ? 'M' : a.type==X86_OP_IMM ? 'I' : '?';
                form += std::to_string(a.size);
            }
            const auto &insn = *readers[0].out;
            const unsigned prefix = insn.bytes[0];
            form += prefix==0xc4 ? "/vex3" : prefix==0xc5 ? "/vex2" : prefix==0x62 ? "/evex" : "/legacy";
            for(unsigned j=0;j<x.op_count;++j) {
                const auto &a=x.operands[j], &b=y.operands[j];
                if(a.type!=X86_OP_MEM)continue;
                if(a.mem.segment!=b.mem.segment || a.mem.base!=b.mem.base || a.mem.index!=b.mem.index || a.mem.scale!=b.mem.scale || a.mem.disp!=b.mem.disp) return 9;
                form += "/op"+std::to_string(j)+"a"+std::to_string(a.access);
                const char *base = a.mem.base==X86_REG_INVALID?"abs":a.mem.base==X86_REG_RIP||a.mem.base==X86_REG_EIP?"ip":"base";
                form+="/";form+=base;
                form+=a.mem.index==X86_REG_INVALID?"":"-index";
                form+=(x.encoding.modrm_offset && (x.modrm&7)==4 && x.addr_size!=2)?"-sib":"";
                if(a.mem.segment!=X86_REG_INVALID)form+="-seg";
                form+="/d"+std::to_string(x.encoding.disp_size);
            }
            for(unsigned j=0;j<insn.size && j<6;++j) {
                static constexpr char hex[]="0123456789abcdef";
                const auto byte=insn.bytes[j];head+=hex[byte>>4];head+=hex[byte&15];
            }
            const char *name=cs_insn_name(readers[0].handle,insn.id);
            auto &g=families[{name?name:insn.mnemonic,form}];
            ++g.count[0];for(unsigned j=0;j<4;++j)g.count[j+1]+=fallback[j];
            if (fallback[2] || fallback[3]) ++g.encodings[head];
            digest = digest*131 + insn.address + insn.id + insn.size;
            offset+=insn.size;consumed+=insn.size;++accepted;
        }
    }
    if (!extents.eof()) return 4;
    std::ofstream tags(argv[4],std::ios::binary);tags.write(reinterpret_cast<const char*>(route.data()),route.size());tags.close();
    if(!tags)return 15;
    std::printf("total\t%llu\t%llu\t%llu\t%llu", (unsigned long long)accepted,
                (unsigned long long)rejected,(unsigned long long)consumed,(unsigned long long)digest);
    for(auto v:misses) std::printf("\t%llu",(unsigned long long)v);
    std::puts("");
    for(auto &family:families) {
        const auto &g=family.second;
        std::printf("%s\t%s",family.first.first.c_str(),family.first.second.c_str());
        for(auto v:g.count)std::printf("\t%llu",(unsigned long long)v);
        auto biggest=g.encodings.end();
        for(auto it=g.encodings.begin();it!=g.encodings.end();++it)
            if(biggest==g.encodings.end()||it->second>biggest->second)biggest=it;
        if(biggest!=g.encodings.end())std::printf("\t%s\t%u",biggest->first.c_str(),biggest->second);
        std::puts("");
    }
    for(auto &r:readers) { cs_free(r.out,1); cs_close(&r.handle); }
}
