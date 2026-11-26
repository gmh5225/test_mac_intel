#include <capstone/capstone.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <vector>
static unsigned cohort(const cs_insn &rec) {
    if (rec.size==1 && rec.bytes[0]==0x90 && rec.id==X86_INS_NOP) return 1;
    if (rec.size==1 && rec.bytes[0]==0xcc && rec.id==X86_INS_INT3) return 2;
    const cs_detail &detail=*rec.detail;
    for(unsigned i=0;i<detail.groups_count;++i) {
        auto g=detail.groups[i];
        if(g==CS_GRP_JUMP || g==CS_GRP_CALL || g==CS_GRP_RET || g==CS_GRP_IRET)
            return 9;
    }
    bool vec=false,mem=false,imm=false,all_reg=detail.x86.op_count!=0;
    for(unsigned i=0;i<detail.x86.op_count;++i) {
        const auto &op=detail.x86.operands[i];
        if(op.type==X86_OP_REG) {
            const auto reg=op.reg;
            vec|=(reg>=X86_REG_XMM0 && reg<=X86_REG_XMM31) ||
                 (reg>=X86_REG_YMM0 && reg<=X86_REG_YMM31) ||
                 (reg>=X86_REG_ZMM0 && reg<=X86_REG_ZMM31) ||
                 (reg>=X86_REG_MM0 && reg<=X86_REG_MM7) || (reg>=X86_REG_K0 && reg<=X86_REG_K7);
        } else all_reg=false;
        mem|=op.type==X86_OP_MEM;
        imm|=op.type==X86_OP_IMM;
    }
    if (!detail.x86.op_count) return 3;
    if (vec) {
        const bool move=std::strstr(rec.mnemonic,"mov")!=nullptr;
        return mem ? (move?4:5) : (move?6:7);
    }
    if (imm && !mem) return 8;
    return mem ? 10 : 11;
}
int main(int argc,char **argv) {
    if(argc!=5)return 1;
    std::ifstream file(argv[2],std::ios::binary),spans(argv[3]);std::ofstream output(argv[4],std::ios::binary);
    if(!file||!spans||!output)return 2;
    std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(file),{}};
    csh h;if(cs_open(CS_ARCH_X86,argv[1][0]=='3'?CS_MODE_32:CS_MODE_64,&h) || cs_option(h,CS_OPT_DETAIL,CS_OPT_ON))return 3;
    auto rec=cs_malloc(h);if(!rec)return 4;
    size_t offset,left;uint64_t ip,counts[12]{};
    while(spans>>offset>>left>>ip) {
        if(offset>bytes.size()||left>bytes.size()-offset)return 5;
        auto pc=static_cast<const uint8_t *>(bytes.data()+offset);
        while(left) {
            const uint64_t at=static_cast<uint64_t>(pc-bytes.data());
            const bool ok=cs_disasm_iter(h,&pc,&left,&ip,rec);const uint8_t kind=ok?cohort(*rec):0;
            if(!ok){++pc;--left;++ip;}
            output.write(reinterpret_cast<const char *>(&at),sizeof(at));output.put(char(kind));++counts[kind];
        }
    }
    if(!spans.eof() || !output)return 6;
    for(auto n:counts)std::printf("%llu ",(unsigned long long)n);
    std::puts("");cs_free(rec,1);return cs_close(&h)!=CS_ERR_OK;
}
