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

extern "C" { uint64_t profile_full_decodes=0, profile_decodes=0, profile_prints=0; }
using Next = decltype(&cs_disasm_iter);

struct Reader {
    csh handle{};
    cs_insn *out{};
    Next step{};
};

int main(int argc, char **argv) {
    if (argc != 4) return 1;
    std::ifstream input(argv[1], std::ios::binary), extents(argv[2]);
    const std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(input), {}};
    if (bytes.empty() || !extents) return 2;
    const cs_mode mode = std::atoi(argv[3]) == 64 ? CS_MODE_64 : std::atoi(argv[3]) == 16 ? CS_MODE_16 : CS_MODE_32;
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
    struct Family { Outcome count{}; std::array<uint64_t,4> decodes{}, prints{}; std::map<std::string, unsigned> encodings; };
    std::map<std::pair<std::string,std::string>,Family> families;
    std::array<uint64_t,4> misses{}, signatures{};
    auto hash=[](uint64_t h, const void *buf, size_t n) {
        auto p=static_cast<const unsigned char *>(buf);
        for(size_t i=0;i<n;++i) h=(h^p[i])*1099511628211ULL;
        return h;
    };
    uint64_t accepted = 0, rejected = 0, consumed = 0, digest = 0;
    size_t begin, length;
    uint64_t address;
    while (extents >> begin >> length >> address) {
        if (begin > bytes.size() || length > bytes.size()-begin || !length) return 4;
        size_t offset = 0;
        while (offset < length) {
            unsigned valid = 0;
            std::array<unsigned,4> fallback{}, decodes{}, prints{};
            for (unsigned i=0; i<readers.size(); ++i) {
                auto &r = readers[i];
                const auto *start = &bytes[begin+offset], *ptr = start;
                size_t left = length-offset;
                uint64_t ip = address+offset, before = profile_full_decodes;
                const auto prior_decode=profile_decodes, prior_print=profile_prints;
                bool ok = r.step(r.handle,&ptr,&left,&ip,r.out);
                fallback[i] = unsigned(profile_full_decodes-before);
                decodes[i]=unsigned(profile_decodes-prior_decode);prints[i]=unsigned(profile_prints-prior_print);
                if(decodes[i]>1 || prints[i]>1 || (!ok && (ptr!=start || left!=length-offset || ip!=address+offset))) return 9;
                if (fallback[i] > 1 || (ok && (r.out->size != ptr-start ||
                    left+r.out->size != length-offset || ip != address+offset+r.out->size))) return 5;
                if (ok) {
                    ++valid;
                    cs_insn flat;std::memcpy(&flat,r.out,sizeof flat);flat.detail=nullptr;
                    signatures[i]=hash(signatures[i],&flat,sizeof flat);
                    if(r.out->detail) signatures[i]=hash(signatures[i],r.out->detail,offsetof(cs_detail,x86)+sizeof(cs_x86));
                    const auto *first = readers[0].out;
                    if (i && (r.out->id != first->id || r.out->address != first->address ||
                        r.out->size != first->size || std::strcmp(r.out->mnemonic,first->mnemonic) ||
                        std::strcmp(r.out->op_str,first->op_str))) return 6;
                }
            }
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
            // Keep the opcode map, mandatory prefix, register/memory form and SIB shape together.
            const bool has_modrm=x.encoding.modrm_offset!=0; const auto *bytes=insn.bytes;
            const char *prefix=bytes[0]==0x62?"evex":bytes[0]==0xc4?"vex3":bytes[0]==0xc5?"vex2":"legacy";
            form+=":"; form+=prefix;
            if (has_modrm) {uint8_t modrm=bytes[x.encoding.modrm_offset]; form+=modrm>=0xc0?":reg":(modrm&7)==4?":sib":(modrm&0xc7)==5?":ip-or-abs":":base";}
            for(unsigned j=0;j<insn.size;++j) {
                static constexpr char hex[]="0123456789abcdef";
                const auto byte=insn.bytes[j];head+=hex[byte>>4];head+=hex[byte&15];
            }
            const char *name=cs_insn_name(readers[0].handle,insn.id);
            auto &g=families[{name?name:insn.mnemonic,form}];
            ++g.count[0];for(unsigned j=0;j<4;++j){g.count[j+1]+=fallback[j];g.decodes[j]+=decodes[j];g.prints[j]+=prints[j];}
            if (fallback[2] || fallback[3] || prints[2] || prints[3]) ++g.encodings[head];
            digest = digest*131 + insn.address + insn.id + insn.size;
            offset+=insn.size;consumed+=insn.size;++accepted;
        }
    }
    if (!extents.eof()) return 4;
    std::printf("total\t%llu\t%llu\t%llu\t%llu", (unsigned long long)accepted,
                (unsigned long long)rejected,(unsigned long long)consumed,(unsigned long long)digest);
    for(auto v:misses) std::printf("\t%llu",(unsigned long long)v);
    for(auto v:signatures) std::printf("\t%llu",(unsigned long long)v);
    std::puts("");
    for(auto &family:families) {
        const auto &g=family.second;
        std::printf("%s\t%s",family.first.first.c_str(),family.first.second.c_str());
        for(auto v:g.count)std::printf("\t%llu",(unsigned long long)v);
        for(const auto &c:{g.decodes,g.prints})for(auto v:c)std::printf("\t%llu",(unsigned long long)v);
        auto biggest=g.encodings.end();
        for(auto it=g.encodings.begin();it!=g.encodings.end();++it)
            if(biggest==g.encodings.end()||it->second>biggest->second)biggest=it;
        if(biggest!=g.encodings.end())std::printf("\t%s\t%u",biggest->first.c_str(),biggest->second);
        std::puts("");
    }
    for(auto &r:readers) { cs_free(r.out,1); cs_close(&r.handle); }
}
