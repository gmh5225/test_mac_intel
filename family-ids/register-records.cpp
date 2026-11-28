#include <capstone/capstone.h>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <set>
#include <vector>

struct Hash {
    uint64_t value = 14695981039346656037ULL;
    void bytes(const void *ptr, size_t size) {
        const auto *data = static_cast<const uint8_t *>(ptr);
        while (size--) value = (value ^ *data++) * 1099511628211ULL;
    }
    template<class T> void add(T v) { bytes(&v, sizeof(v)); }
};
int main(int argc, char **argv) {
    if (argc != 6) return 1;
    const bool fixed = std::atoi(argv[1]), diet = cs_support(CS_SUPPORT_DIET);
    unsigned option = std::atoi(argv[2]);
    std::ifstream input(argv[3], std::ios::binary);
    const std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(input), {}};
    uint64_t addr = std::strtoull(argv[4], nullptr, 10);
    csh h;
    if (cs_open(CS_ARCH_HPPA, cs_mode(CS_MODE_HPPA_20 | CS_MODE_BIG_ENDIAN), &h)) return 2;
    if (cs_option(h, CS_OPT_DETAIL, option==2 ? CS_OPT_ON|CS_OPT_DETAIL_REAL :
                  option==3 ? CS_OPT_ON|CS_OPT_DETAIL_ALIAS : option ? CS_OPT_ON : CS_OPT_OFF)) return 3;
    if(option==4 && cs_option(h,CS_OPT_TEXT,CS_OPT_OFF)) return 4;
    Hash common, fields, unions;
    unsigned good=0, bad=0, special=0, bad_access=0, bad_regs=0;
    for (size_t off=0; off<bytes.size(); off+=4) {
        const uint8_t *p=bytes.data()+off;
        size_t left=bytes.size()-off;
        uint64_t ip=addr+off;
        cs_insn i{}; cs_detail d{}; i.detail=option ? &d : nullptr;
        bool ok=cs_disasm_iter(h,&p,&left,&ip,&i);
        common.add(ok);common.add(ip);
        if (!ok) {++bad;continue;}
        if(i.size!=4 || ip!=addr+off+4 || p!=bytes.data()+off+4 || left!=bytes.size()-off-4) return 5;
        ++good;common.bytes(&i,offsetof(cs_insn,detail));
        if(!option)continue;
        fields.bytes(&d,offsetof(cs_detail,hppa));
        const auto &a=d.hppa;fields.add(a.op_count);
        std::set<unsigned> reads(d.regs_read,d.regs_read+d.regs_read_count),
                           writes(d.regs_write,d.regs_write+d.regs_write_count);
        special+=!reads.empty()||!writes.empty();
        for(unsigned j=0;j<a.op_count;++j) {
            const auto &o=a.operands[j];fields.add(o.type);
            switch(o.type) {
            case HPPA_OP_REG: case HPPA_OP_IDX_REG:
                fields.add(o.reg);fields.add(o.access);
                if(o.access & CS_AC_READ) reads.insert(o.reg);
                if(o.access & CS_AC_WRITE) writes.insert(o.reg);
                break;
            case HPPA_OP_MEM:
                fields.add(o.mem.base);fields.add(o.mem.space);fields.add(o.access);
                if(o.mem.space!=HPPA_REG_INVALID)reads.insert(o.mem.space);
                if(o.access & CS_AC_READ)reads.insert(o.mem.base);
                if(o.access & CS_AC_WRITE)writes.insert(o.mem.base);
                break;
            case HPPA_OP_IMM: case HPPA_OP_DISP: case HPPA_OP_TARGET:
                fields.add(o.imm);{const cs_ac_type none=CS_AC_INVALID;bad_access+=std::memcmp(&o.access,&none,sizeof(none))!=0;}break;
            default:return 6;
            }
        }
        cs_regs rr,ww; uint8_t nr=0,nw=0;
        cs_err err=cs_regs_access(h,&i,rr,&nr,ww,&nw);
        if(diet ? err!=CS_ERR_DIET : err!=CS_ERR_OK) return 7;
        if(!diet && (nr!=reads.size() || nw!=writes.size() ||
           !std::equal(reads.begin(),reads.end(),rr) || !std::equal(writes.begin(),writes.end(),ww))) ++bad_regs;
        for(unsigned v:reads)unions.add(v);
        unions.add(0xffffffffu);
        for(unsigned v:writes)unions.add(v);
        unions.add(0xffffffffu);
    }
    cs_close(&h);
    std::printf("%u %u %u %llu %llu %llu %u %u\n",good,bad,special,
        (unsigned long long)common.value,(unsigned long long)fields.value,(unsigned long long)unions.value,bad_access,bad_regs);
    return fixed && (bad_access || bad_regs) ? 8:0;
}
