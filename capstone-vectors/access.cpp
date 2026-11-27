#define main common_tests_main
#include "trial-compare.cpp"
#undef main
#include <random>
#include <iterator>
#include <iostream>
struct Query {
    uint16_t regs[132];
    uint8_t nr, nw;
};
static Query query(Session &s, const cs_insn &x, unsigned offset, bool same_count) {
    Query out;
    std::memset(&out,0xa5,sizeof(out));
    check(s.api.regs(s.h,&x,out.regs,&out.nr,out.regs+offset,same_count?&out.nr:&out.nw)==CS_ERR_OK,"access status");
    return out;
}
int main(int argc,char **argv) {
    if (argc!=3) return 1;
    Api before(argv[1]),after(argv[2]);
    Session base(before,CS_ARCH_X86,CS_MODE_64),trial(after,CS_ARCH_X86,CS_MODE_64);
    base.set(CS_OPT_DETAIL,CS_OPT_ON);trial.set(CS_OPT_DETAIL,CS_OPT_ON);
    std::mt19937 rng(34671);
    uint64_t queries=0,first=0,load=0;
    for (unsigned i=0; i<240000; ++i) {
        cs_insn x{};cs_detail d{};x.detail=&d;x.id=X86_INS_MOV;
        auto reg=[&]() -> x86_reg {
            auto v=rng();return x86_reg((v&1) ? (v>>1)%7 : (v>>1)%unsigned(X86_REG_ENDING));
        };
        d.regs_read_count=i%3==0?rng()%std::size(d.regs_read):0;
        d.regs_write_count=i%3==0?rng()%std::size(d.regs_write):0;
        for (unsigned j=0;j<d.regs_read_count;++j)d.regs_read[j]=reg();
        for (unsigned j=0;j<d.regs_write_count;++j)d.regs_write[j]=reg();
        auto &xp=d.x86;xp.op_count=i%4==1?2:rng()%(std::size(xp.operands)+1);
        for (unsigned j=0;j<xp.op_count;++j) {
            auto &op=xp.operands[j];
            const x86_op_type kinds[]={X86_OP_INVALID,X86_OP_REG,X86_OP_MEM,X86_OP_IMM};
            op.type=kinds[rng()%4];op.access=static_cast<cs_ac_type>(rng()%4);
            if ((i%4==1 || i%4==2) && j==0) {op.type=X86_OP_REG;if(i%4==1)op.access=CS_AC_WRITE;}
            if (i%4==1 && j==1)op.type=X86_OP_MEM;
            if (op.type==X86_OP_REG) op.reg=reg();
            if (op.type==X86_OP_MEM) {
                op.mem.segment=i%8==1?X86_REG_INVALID:reg();op.mem.base=reg();
                op.mem.index=i%8==1?X86_REG_INVALID:reg();
            }
        }
        if (i%5==3) {
            xp.op_count=(i/5)%2;
            xp.operands[0].type=X86_OP_IMM;
            d.regs_read_count=(i/10)%5;d.regs_write_count=(i/50)%5;
            for (unsigned j=0;j<d.regs_read_count;++j)d.regs_read[j]=reg();
            for (unsigned j=0;j<d.regs_write_count;++j)d.regs_write[j]=reg();
        }
        const bool seed=!d.regs_read_count && !d.regs_write_count && xp.op_count && xp.operands[0].type==X86_OP_REG;
        first+=seed;
        load+=seed && xp.op_count==2 && xp.operands[0].access==CS_AC_WRITE && xp.operands[1].type==X86_OP_MEM && !xp.operands[1].mem.segment && !xp.operands[1].mem.index;
        for (unsigned offset:{0u,1u,4u,64u}) for (bool same:{false,true}) {
            Query a=query(base,x,offset,same),b=query(trial,x,offset,same);
            if (std::memcmp(a.regs,b.regs,sizeof a.regs) || a.nr!=b.nr || a.nw!=b.nw) return 2;
            ++queries;
        }
    }
    std::cout<<queries<<" "<<first<<" "<<load<<"\n";
}
