#include <capstone/capstone.h>
#include "arch/X86/X86ScanAdapter.h"
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <string>
#include <vector>

extern "C" {
uint64_t profile_stage[4]{};
}
using Vector = std::array<uint64_t, 8>;
struct Reader {
    csh handle{};
    cs_insn *record{};
    decltype(&cs_disasm_iter) next{};
    uint64_t digest{};
    Vector counts{};
};
static uint64_t snapshot(csh h, const cs_insn *insn) {
    uint64_t hash = 14695981039346656037ULL;
    auto value = [&](uint64_t x) { hash = (hash ^ x) * 1099511628211ULL; };
    auto text = [&](const char *s) { while (*s) value(static_cast<unsigned char>(*s++)); value(0); };
    const auto *d = insn->detail;
    bool detail = d != nullptr;
    value(insn->id);
        value(insn->alias_id);
        value(insn->address);
        value(insn->size);
        for (unsigned i = 0; i != insn->size; ++i)
          value(insn->bytes[i]);
        text(insn->mnemonic);
        text(insn->op_str);
        value(insn->is_alias);
        value(insn->usesAliasDetails);
        value(insn->illegal);
        if (detail) {
          value(d->writeback);
          value(d->groups_count);
          for (unsigned i = 0; i < d->groups_count; ++i)
            value(d->groups[i]);
          value(d->regs_read_count);
          value(d->regs_write_count);
          for (unsigned i = 0; i < d->regs_read_count; ++i)
            value(d->regs_read[i]);
          for (unsigned i = 0; i < d->regs_write_count; ++i)
            value(d->regs_write[i]);
          cs_regs reads{}, writes{};
          uint8_t nr = 0, nw = 0;
          value(cs_regs_access(h, insn, reads, &nr, writes, &nw));
          value(nr);
          value(nw);
          for (unsigned i = 0; i < nr; ++i)
            value(reads[i]);
          for (unsigned i = 0; i < nw; ++i)
            value(writes[i]);
          const auto &x = d->x86;
          for (auto v : x.prefix)
            value(v);
          for (auto v : x.opcode)
            value(v);
          value(x.rex);
          value(x.rex2);
          value(x.addr_size);
          value(x.modrm);
          value(x.sib);
          value(x.disp);
          value(x.sib_index);
          value(x.sib_scale);
          value(x.sib_base);
          value(x.xop_cc);
          value(x.sse_cc);
          value(x.avx_cc);
          value(x.avx_sae);
          value(x.avx_rm);
          value(x.eflags);
          value(x.op_count);
          value(x.encoding.modrm_offset);
          value(x.encoding.disp_offset);
          value(x.encoding.disp_size);
          value(x.encoding.imm_offset);
          value(x.encoding.imm_size);
          for (unsigned i = 0; i < x.op_count; ++i) {
            const auto &o = x.operands[i];
            value(o.type);
            value(o.size);
            value(o.access);
            value(o.avx_bcast);
            value(o.avx_zero_opmask);
            if (o.type == X86_OP_REG)
              value(o.reg);
            if (o.type == X86_OP_IMM)
              value(o.imm);
            if (o.type == X86_OP_MEM) {
              value(o.mem.segment);
              value(o.mem.base);
              value(o.mem.index);
              value(o.mem.scale);
              value(o.mem.disp);
            }
          }
        }
    return hash;
}
int main(int argc, char **argv) {
    if (argc != 4) return 1;
    std::ifstream file(argv[1],std::ios::binary), ranges(argv[2]);
    const std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(file),{}};
    if (bytes.empty() || !ranges) return 2;
    const auto mode = std::stoi(argv[3]) == 64 ? CS_MODE_64 : CS_MODE_32;
    std::array<Reader,4> readers{};
    for (unsigned i=0;i<4;++i) {
        auto &r = readers[i];
        if (cs_open(CS_ARCH_X86,mode,&r.handle) || cs_option(r.handle,CS_OPT_DETAIL,(i&1)?CS_OPT_ON:CS_OPT_OFF)) return 3;
        r.next = i<2 ? cs_disasm_iter : X86_disasmIterText;
        r.record = cs_malloc(r.handle);
        if (!r.record) return 4;
    }
    std::map<std::string,std::array<uint64_t,5>> families;
    uint64_t accepted=0, rejected=0, covered=0, boundary=0, check_public[2]{};
    size_t start,length;
    uint64_t ip;
    while (ranges>>start>>length>>ip) {
        if (start>bytes.size() || !length || length>bytes.size()-start) return 5;
        for (size_t n=0;n<length;) {
            unsigned width=0;
            std::array<uint64_t,4> checks{};
            std::array<unsigned,4> generic{};
            for(unsigned i=0;i<4;++i) {
                auto &r=readers[i]; auto *detail=r.record->detail;
                std::memset(r.record,0,sizeof(*r.record)); r.record->detail=detail;
                if (detail) std::memset(detail,0,sizeof(*detail));
                auto *first=bytes.data()+start+n, *cursor=first; size_t left=length-n; uint64_t address=ip+n;
                std::array<uint64_t,4> before{};
                std::memcpy(before.data(),profile_stage,sizeof(profile_stage));
                const bool valid=r.next(r.handle,&cursor,&left,&address,r.record);
                const unsigned size=valid?r.record->size:0;
                if ((valid && (!size || size>length-n)) || cursor!=first+size || left!=length-n-size || address!=ip+n+size || (i && width!=size)) {
                    std::fprintf(stderr,"cursor at %zu bitness %s reader %u\n",start+n,argv[3],i);return 6;
                }
                width=size;
                for(unsigned k=0;k<4;++k) {
                    uint64_t delta=profile_stage[k]-before[k];
                    if (delta>1) return 7;
                    if (valid) r.counts[k]+=delta;
                    if (k==0) generic[i]=unsigned(delta);
                    if (k==0 && !valid) r.counts[7]+=delta;
                }
                if (valid) {
                    checks[i]=snapshot(r.handle,r.record);
                    r.digest=r.digest*131+checks[i];
                    if (generic[i]) {
                        r.counts[4]+=std::strlen(r.record->mnemonic);
                        r.counts[5]+=std::strlen(r.record->op_str);
                        if (r.record->detail) r.counts[6]+=r.record->detail->x86.op_count;
                    }
                }
            }
            if (!width) {++rejected;++covered;++n;continue;}
            for (unsigned i=0;i<2;++i) check_public[i]+=checks[i]!=checks[i+2];
            const auto *record=readers[0].record;
            std::string key=record->mnemonic;
            auto &row=families[key];++row[0];
            for(unsigned i=0;i<4;++i) row[1+i]+=generic[i];
            boundary=boundary*131+record->address+record->id+record->size;
            ++accepted;covered+=width;n+=width;
        }
    }
    if (!ranges.eof()) return 8;
    auto number=[](uint64_t val){std::printf("\t%llu",(unsigned long long)val);};
    std::printf("total");
    for(auto val:{accepted,rejected,covered,boundary,check_public[0],check_public[1]}) number(val);
    std::puts("");
    for(auto &r:readers) {
        std::printf("reader");number(r.digest);for(auto val:r.counts)number(val);std::puts("");
        cs_free(r.record,1);cs_close(&r.handle);
    }
    for(const auto &entry:families){
        std::printf("family\t%s",entry.first.c_str());for(auto val:entry.second)number(val);std::puts("");
    }
}
